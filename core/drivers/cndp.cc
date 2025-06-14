// SPDX-License-Identifier: BSD-3-Clause
// Copyright 2019-2021 Intel Corporation.

#include "cndp.h"
#include <algorithm>        // std::min
#include <bsd/string.h>     // for strlcpy
#include <cne_common.h>     // for MEMPOOL_CACHE_MAX_SIZE, __cne_unused
#include <cne_lport.h>      // for lport_cfg
#include <cne_mmap.h>       // for mmap_addr, mmap_alloc, mmap_size, mmap_t
#include <cne_system.h>     // for cne_device_socket_id
#include <filesystem>       // std::filesystem::exists
#include <fstream>          // std::ifstream
#include <getopt.h>         // for getopt_long, option
#include <glog/logging.h>   // for logging
#include <jcfg.h>           // for jcfg_obj_t, jcfg_umem_t, jcfg_opt_t
#include <jcfg_process.h>   // for jcfg_process
#include <metrics.h>        // for cndp metrics
#include <netdev_funcs.h>   // netdev_get_mac_addr
#include <netinet/ether.h>  // mac_addr
#include <pktdev.h>         // for pktdev_rx_burst, pktdev_tx_burst
#include <pktdev_api.h>  // for pktdev_buf_alloc, pktdev_close, pktdev_port_setup
#include <pktmbuf.h>     // for pktmbuf_pool_create, pktmbuf_info_t
#include <pmd_af_xdp.h>  // for PMD_NET_AF_XDP_NAME
#include <rte_mbuf.h>    // rte_mbuf
#include <stdio.h>       // for NULL, printf, EOF
#include <stdlib.h>      // for free, calloc
#include <string.h>      // for strcmp
#include <strings.h>     // for strcasecmp
#include <thread>        // std::thread::id
#include <unistd.h>      // usleep

CommandResponse CndpPort::Init(const bess::pb::CndpPortArg &arg) {
  jsonc_file_ = arg.jsonc_file();
  LOG(INFO) << "CNDP parse jsonc file = " << jsonc_file_;
  if (!std::filesystem::exists(jsonc_file_)) {
    LOG(ERROR) << "jsonc file doesn't exist";
    return CommandFailure(EINVAL, "jsonc file doesn't exist");
  }

  // Register this thread with CNDP if required.
  if (CndpSingleton::CndpRegisterThread("Init") < 0) {
    const char *err_msg = "Register thread with CNDP failed";
    LOG(ERROR) << err_msg;
    return CommandFailure(EINVAL, "%s", err_msg);
  }

  // Get/Create CNDP instance.
  cndp_instance_ = &CndpSingleton::GetInstance(jsonc_file_);
  if (!cndp_instance_->IsConfigured()) {
    std::string err = "CNDP configuration failed for jsonc file: " +
                      std::filesystem::canonical(jsonc_file_).string();
    const char *err_msg = err.c_str();
    LOG(ERROR) << err_msg;
    return CommandFailure(EINVAL, "%s", err_msg);
  }

  // Check if lports are present.
  int num_lports = cndp_instance_->GetNumLports();
  if (num_lports <= 0) {
    const char *err_msg = "No lports found in jsonc file";
    LOG(ERROR) << err_msg;
    return CommandFailure(EINVAL, "%s", err_msg);
  }

  // Validate lport index.
  lport_index_ = arg.lport_index();
  if (lport_index_ >= (uint32_t)num_lports) {
    const char *err_msg = "Invalid lport index";
    LOG(ERROR) << err_msg << " lport index = " << lport_index_;
    LOG(WARNING) << "lport index should be >=0 and <" << num_lports;
    return CommandFailure(EINVAL, "%s", err_msg);
  }
  LOG(INFO) << "CNDP lport index = " << lport_index_;

  // Get lport instance.
  lport_ = cndp_instance_->GetLportFromIndex(lport_index_);
  if (lport_ == nullptr) {
    const char *err_msg = "CNDP jcfg lport is null";
    LOG(ERROR) << err_msg;
    return CommandFailure(EINVAL, "%s", err_msg);
  }

  // Get fwd port from lport.
  lport_fport_ = cndp_instance_->GetFwdPort(lport_);
  if (lport_fport_ == nullptr) {
    const char *err_msg = "CNDP fwd port is null";
    LOG(ERROR) << err_msg;
    return CommandFailure(EINVAL, "%s", err_msg);
  }

  if (lport_fport_->pkt_api == PKTDEV_PKT_API) {
    // Reset pkt_recv_vector_
    pkt_recv_vector_.fill(nullptr);
  }

  // Reset stats.
  CndpStats(true);

  // Get mac address for this lport.
  struct ether_addr mac_addr;
  if (lport_fport_->pkt_api == XSKDEV_PKT_API) {
    netdev_get_mac_addr(lport_fport_->xsk->ifname, &mac_addr);
  } else {
    pktdev_macaddr_get(lport_fport_->lport, &mac_addr);
  }

  // Fill mac address of netdev in Bess port conf_.
  memcpy(conf_.mac_addr.bytes, mac_addr.ether_addr_octet,
         sizeof(mac_addr.ether_addr_octet));

  // Get CPU socket id.
  if (lport_fport_->pkt_api == XSKDEV_PKT_API) {
    lport_socket_id_ = CndpSingleton::GetSocketId(lport_fport_->xsk->ifname);
  } else {
    // Get CPU socket id for this lport.
    lport_socket_id_ = cndp_instance_->GetSocketId(lport_fport_->lport);
  }
  if (lport_socket_id_ < 0) {
    LOG(WARNING) << "Unable to get a valid CPU socket id. Using 0 by default";
    lport_socket_id_ = 0;
  }

  return CommandSuccess();
}

void CndpPort::DeInit() {
  LOG(INFO) << "Called CndpPort::DeInit()";

  if (cndp_instance_ != nullptr) {
    cndp_instance_->Quit();
    cndp_instance_ = nullptr;
  }
}

placement_constraint CndpPort::GetNodePlacementConstraint() const {
  return (placement_constraint)(1ull << lport_socket_id_);
}

bool CndpPort::ReplenishRecvVector(int cnt) {
  DCHECK_LE(cnt, bess::PacketBatch::kMaxBurst);
  bool allocated =
      current_worker.packet_pool()->AllocBulk(pkt_recv_vector_.data(), cnt);
  if (!allocated) {
    LOG(ERROR) << "packet_pool() allocation failed";
  }
  return allocated;
}

void CndpPort::FreeRecvVector() {
  for (auto *pkt : pkt_recv_vector_) {
    bess::Packet::Free(pkt);
  }
}

int CndpPort::RecvPackets(queue_t qid __cne_unused, bess::Packet **pkts,
                          int cnt) {
  // Register this thread with CNDP if required.
  if (CndpSingleton::CndpRegisterThread("CndpRecvPackets") < 0) {
    LOG(ERROR) << "Register thread with CNDP failed";
    return 0;
  }

  // Read cnt packets from lport.
  fwd_port *fport = lport_fport_;
  if (fport == nullptr) {
    LOG(ERROR) << "fwd port is NULL. Can't read packets from lport";
    return 0;
  }

  if (cnt <= 0 || pkts == nullptr) {
    return 0;
  }

  uint16_t num_pkts_read = 0;
  if (fport->pkt_api == XSKDEV_PKT_API) {
    num_pkts_read = XskdevRecvPackets(fport, pkts, cnt);
  } else {
    num_pkts_read = PktdevRecvPackets(fport, pkts, cnt);
  }

  return num_pkts_read;
}

int CndpPort::SendPackets(queue_t qid __cne_unused, bess::Packet **pkts,
                          int cnt) {
  // Register this thread with CNDP if required.
  if (CndpSingleton::CndpRegisterThread("CndpSendPackets") < 0) {
    LOG(ERROR) << "Register thread with CNDP failed";
    return 0;
  }

  fwd_port *fport = lport_fport_;
  if (fport == nullptr) {
    LOG(ERROR) << "fwd port is NULL. Can't send packets from lport";
    return 0;
  }

  if (cnt <= 0 || pkts == nullptr) {
    return 0;
  }

  // Send pkts.
  int sent = 0;
  if (fport->pkt_api == XSKDEV_PKT_API) {
    sent = XskdevSendPackets(fport, pkts, cnt);
  } else {
    sent = PktdevSendPackets(fport, pkts, cnt);
  }

  return sent;
}

uint16_t CndpPort::XskdevRecvPackets(struct fwd_port *fport,
                                     bess::Packet **pkts, int cnt) {
  return xskdev_rx_burst(fport->xsk, (void **)pkts, cnt);
}

uint16_t CndpPort::PktdevRecvPackets(struct fwd_port *fport,
                                     bess::Packet **pkts, int cnt) {
  pktmbuf_t **mbufs = &fport->mbufs[0];
  uint16_t num_pkts_read = pktdev_rx_burst(fport->lport, mbufs, cnt);

  if (num_pkts_read == 0) {
    // No packets read.
    return 0;
  }

  bool ret = ReplenishRecvVector(num_pkts_read);
  if (!ret) {
    pktmbuf_free_bulk(mbufs, num_pkts_read);
    LOG(ERROR) << "Allocation of vector failed";
    return 0;
  }

  for (uint16_t i = 0; i < num_pkts_read; i++) {
    pktmbuf_t *pkt_mbuf = fport->mbufs[i];
    if ((pkt_mbuf == nullptr) || (pkt_mbuf->data_len == 0)) {
      pktmbuf_free_bulk(mbufs, num_pkts_read);
      FreeRecvVector();
      LOG(ERROR) << "pkt_mbuf is either NULL of of zero length";
      return 0;
    }

    bess::Packet *pkt = pkt_recv_vector_[i];
    void *pktmbuf_data = pktmbuf_mtod(pkt_mbuf, void *);
    int copy_len = std::min(pkt_mbuf->data_len, pkt->tailroom());
    bess::utils::CopyInlined(pkt->append(copy_len), pktmbuf_data, copy_len,
                             true);
    pkts[i] = pkt;
  }
  // Free mbufs.
  pktmbuf_free_bulk(mbufs, num_pkts_read);

  return num_pkts_read;
}

uint16_t CndpPort::XskdevSendPackets(struct fwd_port *fport,
                                     bess::Packet **pkts, int cnt) {
  struct rte_mbuf *mbuf = (struct rte_mbuf *)(pkts[0]);
  bool same_pool = (mbuf->pool->pool_id == fport->bess_pool->pool()->pool_id);
  if (same_pool) {
    // Packets belong to same memory pool.
    return xskdev_tx_burst(fport->xsk, (void **)pkts, cnt);
  } else {
    LOG_FIRST_N(INFO, 1) << "Packets belong to different mempools";
    bess::Packet *alloc_pkts[CNDP_MAX_BURST];
    uint16_t n_pkts = fport->xsk->buf_mgmt.buf_alloc(
        fport, (void **)alloc_pkts,
        ((cnt < CNDP_MAX_BURST) ? cnt : CNDP_MAX_BURST));

    if (n_pkts == 0) {
      LOG_FIRST_N(WARNING, 10) << "Cannot allocate any buffers to send packets";
      return 0;
    }

    if (n_pkts < cnt) {
      LOG_FIRST_N(WARNING, 10)
          << "Cannot allocate enough buffers to send all packets"
          << " Requested=" << cnt << ", Allocated=" << n_pkts;
    }
    // Copy packets across mempools.
    for (uint16_t i = 0; i < n_pkts; i++) {
      bess::utils::CopyInlined(alloc_pkts[i]->append(pkts[i]->total_len()),
                               pkts[i]->head_data(), pkts[i]->total_len(),
                               true);
    }

    uint16_t sent = xskdev_tx_burst(fport->xsk, (void **)alloc_pkts, n_pkts);
    if (sent < n_pkts) {
      LOG_FIRST_N(WARNING, 10) << "Free packets which are not sent"
                               << " Requested=" << n_pkts << ", Sent=" << sent;
      // Free allocated packets which are not sent.
      fport->xsk->buf_mgmt.buf_free(fport, (void **)(alloc_pkts + sent),
                                    n_pkts - sent);
    }
    // Free BESS packets which are sent.
    bess::Packet::Free(pkts, sent);
    return sent;
  }

  return 0;
}

uint16_t CndpPort::PktdevSendPackets(struct fwd_port *fport,
                                     bess::Packet **pkts, int cnt) {
  pktmbuf_t **mbufs = &fport->mbufs[0];
  uint16_t n_pkts = pktdev_buf_alloc(fport->lport, mbufs, cnt);

  if (n_pkts == 0) {
    LOG_FIRST_N(WARNING, 10) << "Cannot allocate any buffers to send packets";
    return 0;
  }

  if (n_pkts < cnt) {
    LOG_FIRST_N(WARNING, 10)
        << "Cannot allocate enough buffers to send all packets"
        << " Requested=" << cnt << ", Allocated=" << n_pkts;
  }

  for (uint16_t i = 0; i < n_pkts; i++) {
    pktmbuf_t *pkt_mbuf = fport->mbufs[i];
    bess::Packet *pkt = pkts[i];
    void *pktmbuf_data = pktmbuf_mtod(pkt_mbuf, void *);
    bess::utils::CopyInlined(pktmbuf_data, pkt->head_data<const u_char *>(),
                             pkt->data_len(), true);
    pkt_mbuf->data_len = pkt->data_len();
  }

  // Send pkts.
  uint16_t sent = pktdev_tx_burst(fport->lport, mbufs, n_pkts);
  if (sent < n_pkts) {
    LOG_FIRST_N(WARNING, 10) << "Free packets which are not sent"
                             << " Requested=" << n_pkts << ", Sent=" << sent;
    // Free allocated CNDP pktmbufs which are not sent.
    pktmbuf_free_bulk(mbufs + sent, n_pkts - sent);
  }

  // Free packets which are sent.
  bess::Packet::Free(pkts, sent);

  return sent;
}

void CndpPort::CndpStats(bool reset) {
  fwd_port *fport = lport_fport_;
  if (fport) {
    if (reset) {
      LOG(INFO) << "Reset cndp stats";
      memset(&cndp_stats_, 0, sizeof(cndp_stats_));
      if (fport->pkt_api == XSKDEV_PKT_API) {
        xskdev_stats_reset(fport->xsk);
      } else {
        pktdev_stats_reset(fport->lport);
      }

      return;
    }
    if (fport->pkt_api == XSKDEV_PKT_API) {
      xskdev_stats_get(fport->xsk, &cndp_stats_);
    } else {
      pktdev_stats_get(fport->lport, &cndp_stats_);
    }
  }

  // Log first two packets.
  LOG_FIRST_N(INFO, 2) << "CndpStats:packets = " << cndp_stats_.ipackets;
  LOG_FIRST_N(INFO, 2) << "CndpStats:bytes = " << cndp_stats_.ibytes;
  LOG_FIRST_N(INFO, 2) << "CndpStats:dropped = " << cndp_stats_.imissed;
}

void CndpPort::CollectStats(bool reset) {
  if (reset) {
    CndpStats(true);
    return;
  }
  // Get CNDP port stats.
  CndpStats(false);

  // Update BESS CNDP port stats.
  port_stats_.inc.packets = cndp_stats_.ipackets;
  port_stats_.inc.bytes = cndp_stats_.ibytes;
  port_stats_.inc.dropped = cndp_stats_.imissed;
  port_stats_.out.packets = cndp_stats_.opackets;
  port_stats_.out.bytes = cndp_stats_.obytes;
  port_stats_.out.dropped = cndp_stats_.odropped;

  // There is no BESS queue stats for CNDP lport.
  packet_dir_t dir;
  queue_t qid;
  dir = PACKET_DIR_INC;
  for (qid = 0; qid < num_queues[dir]; qid++) {
    queue_stats[dir][qid].packets = 0;
    queue_stats[dir][qid].bytes = 0;
    queue_stats[dir][qid].dropped = 0;
  }

  dir = PACKET_DIR_OUT;
  for (qid = 0; qid < num_queues[dir]; qid++) {
    queue_stats[dir][qid].packets = 0;
    queue_stats[dir][qid].bytes = 0;
    queue_stats[dir][qid].dropped = 0;
  }
}

// CNDP memory pool.
CndpPacketPoolMap CndpSingleton::cndp_packet_pool_;

// CndpSingleton public member functions.
CndpSingleton &CndpSingleton::GetInstance(const std::string &jsonc_file) {
  // Cndp instance will be lazy initialized.
  static CndpSingleton instance(jsonc_file);
  // Reconfigure CNDP if JSONC file has changed.
  if (instance.jsonc_file_ != jsonc_file) {
    LOG(INFO) << "Jsonc file changed. Reconfigure CNDP";
    memset(&(instance.fwd_), 0, sizeof(instance.fwd_));
    if (instance.ParseFile(jsonc_file.c_str(), &instance.fwd_) < 0) {
      LOG(ERROR) << "CNDP parse jsonc failed";
      instance.configured_ = false;
      return instance;
    }
    instance.configured_ = true;
    instance.jsonc_file_ = jsonc_file;
  }
  return instance;
}

void CndpSingleton::Quit() {
  // If CNDP is not configured return.
  if (!configured_) {
    return;
  }
  // Register this thread with CNDP if required.
  if (CndpSingleton::CndpRegisterThread("CndpQuit") < 0) {
    LOG(ERROR) << "Register thread with CNDP failed";
    return;
  }
  if (jcfg_thread_foreach(fwd_.jinfo, CndpSingleton::CndpQuit, &fwd_) < 0) {
    LOG(WARNING) << "Error while quitting CNDP";
  }
  // Reset jsonc fle;
  jsonc_file_ = "";
  configured_ = false;
  LOG(INFO) << "CNDP Quitted";
}

bool CndpSingleton::IsConfigured() {
  return configured_;
}

jcfg_lport_t *CndpSingleton::GetLportFromIndex(int index) {
  return jcfg_lport_by_index(fwd_.jinfo, index);
}

int CndpSingleton::GetNumLports() {
  return jcfg_num_lports(fwd_.jinfo);
}

int CndpSingleton::CndpRegisterThread(const std::string &register_name) {
  if (!cne_check_registration()) {
    return cne_register(register_name.c_str());
  } else {
    return cne_id();
  }
}

fwd_port *CndpSingleton::GetFwdPort(const jcfg_lport_t *lport) {
  fwd_port *fport = nullptr;
  if (lport) {
    if (lport->priv_) {
      fport = (fwd_port *)lport->priv_;
    }
  }
  return fport;
}

int CndpSingleton::GetSocketId(char *ifname) {
  return cne_device_socket_id(ifname);
}

int CndpSingleton::GetSocketId(uint32_t lport_id) {
  return pktdev_socket_id(lport_id);
}

bess::PacketPool *CndpSingleton::GetCndpPacketPool(std::string umem_name,
                                                   int socket_id) {
  CndpPacketPoolMap::iterator pos = cndp_packet_pool_.find(umem_name);
  if (pos == cndp_packet_pool_.end()) {
    return nullptr;
  } else {
    if (pos->second && (socket_id >= 0) && (socket_id < RTE_MAX_NUMA_NODES)) {
      CndpPacketPoolArray arr = *(pos->second);
      return arr[socket_id];
    } else {
      return nullptr;
    }
  }
}

// CndpSingleton private member functions.
CndpSingleton::CndpSingleton(const std::string &jsonc_file)
    : jsonc_file_(jsonc_file) {
  configured_ = false;
  memset(&fwd_, 0, sizeof(fwd_));
  if (cne_init() < 0) {
    LOG(ERROR) << "CNDP initialization failed";
    return;
  }

  // Parse JSONC file.
  if (ParseFile(jsonc_file.c_str(), &fwd_) < 0) {
    LOG(ERROR) << "CNDP parse jsonc failed";
    return;
  }
  configured_ = true;
  LOG(INFO) << "CNDP instance created";
}

int CndpSingleton::ParseFile(const char *json_file, struct fwd_info *fwd) {
  int flags = JCFG_PARSE_FILE;
  fwd->jinfo = jcfg_parser(flags, (const char *)json_file);
  if (fwd->jinfo == NULL) {
    LOG(ERROR) << "*** Did not find any configuration to use ***";
    return -1;
  }

  if (jcfg_process(fwd->jinfo, flags, JcfgProcessCallback, fwd)) {
    LOG(ERROR) << "*** Invalid configuration ***";
    return -1;
  }

  if (metrics_init(fwd)) {
    LOG(ERROR) << "*** Failed to start metrics support ***";
    return -1;
  }

  return 0;
}

pkt_api_t CndpSingleton::GetPktApi(const char *type) {
  if (type) {
    size_t nlen = strnlen(type, MAX_STRLEN_SIZE);

    if (!strncasecmp(type, XSKDEV_API_NAME, nlen))
      return XSKDEV_PKT_API;
    else if (!strncasecmp(type, PKTDEV_API_NAME, nlen))
      return PKTDEV_PKT_API;
  }

  return UNKNOWN_PKT_API;
}

bool CndpSingleton::CreatePktmbufPool(jcfg_umem_t *umem, jcfg_info_t *j) {
  uint32_t cache_sz;
  char *umem_addr;

  /* The UMEM object describes the total size of the UMEM space */
  umem->mm = mmap_alloc(umem->bufcnt, umem->bufsz, (mmap_type_t)umem->mtype);
  if (umem->mm == NULL)
    LOG(ERROR) << " Failed to allocate mmap memory of size:"
               << umem->bufcnt * umem->bufsz;

  if (jcfg_default_get_u32(j, "cache", &cache_sz))
    cache_sz = MEMPOOL_CACHE_MAX_SIZE;

  umem_addr = (char *)mmap_addr(umem->mm);

  /* Create the pktmbuf pool for each region defined */
  for (int i = 0; i < umem->region_cnt; i++) {
    pktmbuf_info_t *pi;
    region_info_t *ri = &umem->rinfo[i];
    char name[PKTMBUF_INFO_NAME_SZ] = {0};

    /* Find the starting memory address in UMEM for the pktmbuf_t buffers */
    ri->addr = umem_addr;
    umem_addr += (ri->bufcnt * umem->bufsz);

    /* Initialize a pktmbuf_info_t structure for each region in the UMEM space
     */
    pi = pktmbuf_pool_create(ri->addr, ri->bufcnt, umem->bufsz, cache_sz, NULL);
    if (!pi) {
      mmap_free(umem->mm);
      LOG(ERROR) << "pktmbuf_pool_init() failed for region: " << i;
      return false;
    }
    snprintf(name, sizeof(name), "%s-%d", umem->name, i);
    pktmbuf_info_name_set(pi, name);

    ri->pool = pi;
  }

  return true;
}

bool CndpSingleton::CreateCndpPacketPool(std::string umem_name,
                                         size_t capacity) {
  CndpPacketPoolArray *arr = new CndpPacketPoolArray();
  if (arr == nullptr) {
    LOG(ERROR) << "Error creating Cndp Packet Pool";
    return false;
  }
  for (int sid = 0; sid < bess::NumNumaNodes(); sid++) {
    bess::PacketPool *pool = new bess::DpdkPacketPool(capacity, sid);
    if (pool == nullptr) {
      LOG(ERROR) << "Error creating Cndp Packet Pool from Dpdk Packet pool";
      return false;
    }
    (*arr)[sid] = pool;
  }
  cndp_packet_pool_.emplace(umem_name, arr);
  return true;
}

uintptr_t CndpSingleton::GetUmemBaseAddr(struct rte_mempool *mp) {
  struct rte_mempool_memhdr *memhdr;
  memhdr = STAILQ_FIRST(&mp->mem_list);
  if (memhdr == nullptr) {
    return (uintptr_t) nullptr;
  }
  return (uintptr_t)memhdr->addr;
}

uintptr_t CndpSingleton::GetPageAlignedAddr(uintptr_t mem_addr,
                                            uint64_t *align) {
  uintptr_t aligned_addr = mem_addr & ~(getpagesize() - 1);
  if (align != nullptr) {
    *align = mem_addr - aligned_addr;
  }

  return aligned_addr;
}

int CndpSingleton::JcfgProcessCallback(jcfg_info_t *j, void *_obj, void *arg,
                                       int idx __cne_unused) {
  jcfg_obj_t obj;
  struct fwd_info *f = (struct fwd_info *)arg;
  size_t nlen;

  if (!_obj)
    return -1;

  obj.hdr = (jcfg_hdr_t *)_obj;

  nlen = strnlen(obj.opt->name, MAX_STRLEN_SIZE);

  switch (obj.hdr->cbtype) {
    case JCFG_APPLICATION_TYPE:
      break;

    case JCFG_DEFAULT_TYPE:
      break;

    case JCFG_OPTION_TYPE:
      if (!strncmp(obj.opt->name, PKT_API_TAG, nlen)) {
        if (obj.opt->val.type == STRING_OPT_TYPE) {
          f->opts.pkt_api = obj.opt->val.str;
          if (f->pkt_api == UNKNOWN_PKT_API)
            f->pkt_api = CndpSingleton::GetPktApi(f->opts.pkt_api);
        }
      } else if (!strcmp(obj.opt->name, NO_METRICS_TAG)) {
        if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
          f->opts.no_metrics = obj.opt->val.boolean;
      } else if (!strcmp(obj.opt->name, NO_RESTAPI_TAG)) {
        if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
          f->opts.no_restapi = obj.opt->val.boolean;
      } else if (!strcmp(obj.opt->name, ENABLE_CLI_TAG)) {
        if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
          f->opts.cli = obj.opt->val.boolean;
      } else if (!strcmp(obj.opt->name, MODE_TAG)) {
        if (obj.opt->val.type == STRING_OPT_TYPE) {
          f->opts.mode = obj.opt->val.str;
        }
      } else if (!strncmp(obj.opt->name, UDS_PATH_TAG, nlen)) {
        if (obj.opt->val.type == STRING_OPT_TYPE) {
          f->xdp_uds = udsc_handshake(obj.opt->val.str);
          if (f->xdp_uds == NULL) {
            LOG(ERROR) << "CNDP uds handshake failed";
            return -1;
          }
        }
      }
      break;

    case JCFG_UMEM_TYPE: {
      if (f->pkt_api == XSKDEV_PKT_API) {
        LOG(INFO) << "Create UMEM of size = " << obj.umem->bufcnt;
        // Create CNDP Memory Pool.
        bool ret =
            CreateCndpPacketPool(std::string(obj.umem->name), obj.umem->bufcnt);
        if (!ret) {
          LOG(ERROR) << "CNDP Mempool creation failed";
          return -1;
        }
      } else {
        bool ret = CreatePktmbufPool(obj.umem, j);
        if (!ret) {
          LOG(ERROR) << "Pktmbuf creation failed";
          return -1;
        }
      }
      break;
    }
    case JCFG_LPORT_TYPE:
      do {
        jcfg_lport_t *lport = obj.lport;
        struct fwd_port *pd;
        jcfg_umem_t *umem;

        if (lport == nullptr) {
          LOG(ERROR) << "lport is NULL";
          return -1;
        }

        umem = lport->umem;
        if (umem == nullptr) {
          LOG(ERROR) << "UMEM is NULL for this lport id: " << lport->lpid;
          return -1;
        }

        pd = (struct fwd_port *)calloc(1, sizeof(struct fwd_port));
        if (!pd) {
          LOG(ERROR) << "Unable to allocate fwd_port structure";
          return -1;
        }
        pd->pkt_api = f->pkt_api;
        lport->priv_ = pd;

        int ret = 0;
        // Create XSKDEV Socket.
        if (f->pkt_api == XSKDEV_PKT_API) {
          ret = CndpSingleton::CreateXskdevSocket(umem, lport, pd, f);
        } else {
          ret = CndpSingleton::CreatePktdevSocket(umem, lport, pd, f);
        }
        if (ret < 0) {
          LOG(ERROR) << "AF_XDP socket creation failed";
          return -1;
        }
      } while ((0));
      break;

    case JCFG_LGROUP_TYPE:
      break;

    case JCFG_THREAD_TYPE:
      break;
    default:
      return -1;
  }
  return 0;
}

int CndpSingleton::CreateXskdevSocket(jcfg_umem_t *umem, jcfg_lport_t *lport,
                                      struct fwd_port *pd, struct fwd_info *f) {
  struct lport_cfg pcfg;
  memset(&pcfg, 0, sizeof(pcfg));

  // Get BESS memory pool.
  int socket_id = CndpSingleton::GetSocketId(lport->netdev);
  if (socket_id < 0) {
    LOG(WARNING) << "Unable to get a valid CPU socket id. Using 0 by default";
    socket_id = 0;
  }
  bess::PacketPool *bess_pool =
      CndpSingleton::GetCndpPacketPool(lport->umem_name, socket_id);
  if (bess_pool == nullptr) {
    LOG(ERROR) << "Couldn't get CNDP MemPool for umem:" << lport->umem_name;
    return -1;
  }
  pd->bess_pool = bess_pool;
  rte_mempool *mp = bess_pool->pool();
  if (mp == nullptr) {
    LOG(ERROR) << "rte_mempool pointer is NULL";
    return -1;
  }
  LOG(INFO) << "bess rte_mempool name = " << mp->name
            << ", rte_mempool addr = " << mp
            << ", rte_mempool id = " << mp->pool_id;

  // UMEM base and aligned base address.
  void *mp_umem_addr_base = (void *)(CndpSingleton::GetUmemBaseAddr(mp));
  if (mp_umem_addr_base == nullptr) {
    LOG(ERROR) << "UMEM base addr is NULL";
    return -1;
  }
  uint64_t align = 0;
  void *mp_umem_addr_base_align = (void *)CndpSingleton::GetPageAlignedAddr(
      (uintptr_t)mp_umem_addr_base, &align);

  // Framesize in UMEM.
  uint32_t umem_framesize =
      rte_mempool_calc_obj_size(mp->elt_size, mp->flags, NULL);

  // UMEM length.
  size_t mp_umem_len =
      (uint64_t)mp->populated_size * (uint64_t)umem_framesize + align;

  // Calculate buffer headroom.
  size_t buf_headroom =
      mp->header_size + sizeof(struct rte_mbuf) + rte_pktmbuf_priv_size(mp);

  DLOG(INFO) << "RTE memzone Umem addr = " << mp_umem_addr_base_align;
  DLOG(INFO) << "RTE memzone Umem len = " << mp_umem_len;
  DLOG(INFO) << "Populated Size = " << mp->populated_size;
  DLOG(INFO) << "Align = " << align;
  DLOG(INFO) << "RTE memzone hugepaze sz = " << mp->mz->hugepage_sz;
  DLOG(INFO) << "RTE memzone socket id = " << mp->mz->socket_id;
  DLOG(INFO) << "Element size = " << mp->elt_size;
  DLOG(INFO) << "header size = " << mp->header_size;
  DLOG(INFO) << "trailer size = " << mp->trailer_size;
  DLOG(INFO) << "Frame size = " << umem_framesize;
  DLOG(INFO) << "buf_headroom = " << buf_headroom;
  DLOG(INFO) << "Packet size = " << sizeof(bess::Packet);
  DLOG(INFO) << "rte_mbuf size = " << sizeof(rte_mbuf);
  DLOG(INFO) << "rte_mbuf private size = " << rte_pktmbuf_priv_size(mp);
  DLOG(INFO) << "Num memory chunks = " << mp->nb_mem_chunks;
  DLOG(INFO) << "Mempool max Size = " << mp->size;
  DLOG(INFO) << "BESS packet pool size " << bess_pool->Size();
  DLOG(INFO) << "BESS packet pool capacity " << bess_pool->Capacity();

  pcfg.qid = lport->qid;
  pcfg.bufsz = umem_framesize;
  pcfg.rx_nb_desc = XSK_RING_PROD__DEFAULT_NUM_DESCS;
  pcfg.tx_nb_desc = XSK_RING_CONS__DEFAULT_NUM_DESCS;
  pcfg.pmd_opts = lport->pmd_opts;
  pcfg.umem_addr = (char *)mp_umem_addr_base_align;
  pcfg.umem_size = mp_umem_len;
  pcfg.busy_timeout = lport->busy_timeout;
  pcfg.busy_budget = lport->busy_budget;
  pcfg.flags = lport->flags;
  pcfg.flags |= LPORT_USER_MANAGED_BUFFERS;
  pcfg.flags |= LPORT_UMEM_UNALIGNED_BUFFERS;
  pcfg.flags |= (umem->shared_umem == 1) ? LPORT_SHARED_UMEM : 0;
  pcfg.addr = (void *)mp_umem_addr_base_align;
  pcfg.bufcnt = mp->populated_size;
  if (!pcfg.addr) {
    free(pd);
    LOG(ERROR) << "fwd_port freed";
    return -1;
  }
  if (lport->flags & LPORT_UNPRIVILEGED) {
    if (f->xdp_uds)
      pcfg.xsk_uds = f->xdp_uds;
    else {
      LOG(ERROR) << "UDS info struct is null";
      return -1;
    }
  }

  /* Setup the mempool configuration */
  strlcpy(pcfg.pmd_name, lport->pmd_name, sizeof(pcfg.pmd_name));
  strlcpy(pcfg.ifname, lport->netdev, sizeof(pcfg.ifname));
  strlcpy(pcfg.name, lport->name, sizeof(pcfg.name));

  pcfg.buf_mgmt.buf_arg = (void *)pd;
  pcfg.buf_mgmt.buf_alloc = CndpSingleton::CndpBufAlloc;
  pcfg.buf_mgmt.buf_free = CndpSingleton::CndpBufFree;
  pcfg.buf_mgmt.buf_set_len = CndpSingleton::CndpBufSetLen;
  pcfg.buf_mgmt.buf_set_data_len = CndpSingleton::CndpBufSetDataLen;
  pcfg.buf_mgmt.buf_set_data = CndpSingleton::CndpBufSetData;
  pcfg.buf_mgmt.buf_get_data_len = CndpSingleton::CndpBufGetDataLen;
  pcfg.buf_mgmt.buf_get_data = CndpSingleton::CndpBufGetData;
  pcfg.buf_mgmt.buf_get_addr = CndpSingleton::CndpBufGetAddr;
  pcfg.buf_mgmt.buf_inc_ptr = CndpSingleton::CndpBufIncPtr;
  pcfg.buf_mgmt.buf_reset = CndpSingleton::CndpBufReset;
  pcfg.buf_mgmt.buf_headroom = buf_headroom;
  pcfg.buf_mgmt.frame_size = pcfg.bufsz;
  pcfg.buf_mgmt.pool_header_sz = mp->header_size;

  pd->xsk = xskdev_socket_create(&pcfg);
  if (pd->xsk == NULL) {
    free(pd);
    LOG(ERROR) << "xskdev_port_setup() failed";
    return -1;
  }

  return 0;
}

int CndpSingleton::CreatePktdevSocket(jcfg_umem_t *umem, jcfg_lport_t *lport,
                                      struct fwd_port *pd, struct fwd_info *f) {
  struct lport_cfg pcfg;
  memset(&pcfg, 0, sizeof(pcfg));

  pcfg.qid = lport->qid;
  pcfg.bufsz = umem->bufsz;
  pcfg.rx_nb_desc = umem->rxdesc;
  pcfg.tx_nb_desc = umem->txdesc;
  pcfg.umem_addr = (char *)mmap_addr(umem->mm);
  pcfg.umem_size = mmap_size(umem->mm, NULL, NULL);
  pcfg.pmd_opts = lport->pmd_opts;
  pcfg.busy_timeout = lport->busy_timeout;
  pcfg.busy_budget = lport->busy_budget;
  pcfg.flags = lport->flags;
  pcfg.flags |= (umem->shared_umem == 1) ? LPORT_SHARED_UMEM : 0;

  pcfg.addr = jcfg_lport_region(lport, &pcfg.bufcnt);
  if (!pcfg.addr) {
    free(pd);
    return -1;
  }
  pcfg.pi = umem->rinfo[lport->region_idx].pool;
  if (lport->flags & LPORT_UNPRIVILEGED) {
    if (f->xdp_uds)
      pcfg.xsk_uds = f->xdp_uds;
    else
      LOG(ERROR) << "UDS info struct is null";
  }
  /* Setup the mempool configuration */
  strlcpy(pcfg.pmd_name, lport->pmd_name, sizeof(pcfg.pmd_name));
  strlcpy(pcfg.ifname, lport->netdev, sizeof(pcfg.ifname));
  strlcpy(pcfg.name, lport->name, sizeof(pcfg.name));

  pd->lport = pktdev_port_setup(&pcfg);
  if (pd->lport < 0) {
    free(pd);
    return -1;
  }

  return 0;
}

#define foreach_thd_lport(_t, _lp)                               \
  for (int _i = 0; _i < _t->lport_cnt && (_lp = _t->lports[_i]); \
       _i++, _lp = _t->lports[_i])

int CndpSingleton::CndpQuit(jcfg_info_t *j __cne_unused, void *obj, void *arg,
                            int idx __cne_unused) {
  jcfg_thd_t *thd = (jcfg_thd_t *)obj;
  jcfg_lport_t *lport;
  struct fwd_info *fwd = (struct fwd_info *)arg;

  thd->quit = 1;

  if (thd->lport_cnt == 0) {
    LOG(INFO) << "No lports attached to thread " << thd->name;
    return 0;
  } else
    LOG(INFO) << "Close " << thd->lport_cnt << " lports attached to thread "
              << thd->name;

  foreach_thd_lport(thd, lport) {
    struct fwd_port *pd = (struct fwd_port *)lport->priv_;
    LOG(INFO) << "lport " << lport->lpid << " - " << lport->name;

    if (fwd->pkt_api == XSKDEV_PKT_API) {
      xskdev_socket_destroy(pd->xsk);
    } else {
      int ret = pktdev_close(pd->lport);
      if (ret < 0) {
        LOG(ERROR) << "port_close() returned error";
        return ret;
      }

      if (lport->umem) {
        int i;

        for (i = 0; i < lport->umem->region_cnt; i++) {
          pktmbuf_destroy(lport->umem->rinfo[i].pool);
          lport->umem->rinfo[i].pool = NULL;
        }
        mmap_free(lport->umem->mm);
        lport->umem->mm = NULL; /* Make sure we do not free this again */
      }
    }
  }
  // Destroy metrics.
  metrics_destroy();

  fwd->quit = 1;
  return 0;
}

int CndpSingleton::CndpBufAlloc(void *arg, void **bufs, uint16_t nb_bufs) {
  struct fwd_port *pd = (struct fwd_port *)arg;
  bess::PacketPool *bess_pool = pd->bess_pool;
  if (bess_pool == nullptr) {
    return 0;
  }
  bool ret = bess_pool->AllocBulk((bess::Packet **)bufs, nb_bufs);
  if (ret) {
    return nb_bufs;
  }
  return 0;
}

void CndpSingleton::CndpBufFree(void *arg __cne_unused, void **bufs,
                                uint16_t nb_bufs) {
  bess::Packet **pkts = (bess::Packet **)bufs;
  if (pkts != nullptr) {
    for (int i = 0; i < nb_bufs; i++) {
      bess::Packet::Free(pkts[i]);
    }
  }
}

void CndpSingleton::CndpBufSetDataLen(void *mb, int len) {
  rte_mbuf *mbuf = (rte_mbuf *)mb;
  if (mbuf) {
    mbuf->data_len = (uint16_t)len;
    mbuf->pkt_len = (uint16_t)len;
  }
}

void CndpSingleton::CndpBufSetLen(void *mb, int len) {
  rte_mbuf *mbuf = (rte_mbuf *)mb;
  if (mbuf) {
    mbuf->buf_len = (uint16_t)len;
  }
}

void CndpSingleton::CndpBufSetData(void *mb, uint64_t off) {
  rte_mbuf *mbuf = (rte_mbuf *)mb;
  if (mbuf) {
    mbuf->data_off = (uint16_t)off;
  }
}

uint64_t CndpSingleton::CndpBufGetData(void *mb) {
  rte_mbuf *mbuf = (rte_mbuf *)mb;
  if (mbuf) {
    uint64_t data = rte_pktmbuf_mtod(mbuf, uint64_t);
    return data;
  }
  return 0;
}

uint16_t CndpSingleton::CndpBufGetDataLen(void *mb) {
  rte_mbuf *mbuf = (rte_mbuf *)mb;
  if (mbuf) {
    return mbuf->data_len;
  }
  return 0;
}

uint64_t CndpSingleton::CndpBufGetAddr(void *mb) {
  rte_mbuf *mbuf = (rte_mbuf *)mb;
  return (uint64_t)(mbuf);
}

void **CndpSingleton::CndpBufIncPtr(void **mbs) {
  rte_mbuf **mbufs = (rte_mbuf **)mbs;
  if (mbufs) {
    return (void **)++mbufs;
  }
  return nullptr;
}

void CndpSingleton::CndpBufReset(void *mb, uint32_t buf_len, size_t headroom) {
  rte_mbuf *mbuf = reinterpret_cast<rte_mbuf *>(mb);
  if (mbuf) {
    mbuf->buf_len = (uint16_t)buf_len;
    mbuf->data_off = (uint16_t)headroom;
    mbuf->data_len = 0;
  }
}

ADD_DRIVER(CndpPort, "cndp_port",
           "CNDP driver to send/recv n/w packets using AF_XDP socket")
