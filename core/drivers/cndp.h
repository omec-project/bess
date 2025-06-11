// SPDX-License-Identifier: BSD-3-Clause
// Copyright 2019-2021 Intel Corporation.

#ifndef BESS_DRIVERS_CNDP_H_
#define BESS_DRIVERS_CNDP_H_

#include "../port.h"

#include <array>
#include <map>
#include <string>

// CNDP headers.
#include <cne_common.h>   // for __cne_unused
#include <cne_lport.h>    // for lport_stats_t
#include <jcfg.h>         // for jcfg_lport_t, jcfg_info_t, jcfg_lport_foreach
#include <packet_pool.h>  // PacketPool
#include <pktmbuf.h>      // for pktmbuf_t
#include <rte_mempool.h>  // rte_mempool
#include <stdint.h>       // for uint64_t, uint32_t
#include <uds_connect.h>  // UDS utility functions
#include <xskdev.h>       // for xskdev_info_t

#define PKT_API_TAG "pkt_api"       /**< Packet API json tag */
#define NO_METRICS_TAG "no-metrics" /**< json tag for no-metrics */
#define NO_RESTAPI_TAG "no-restapi" /**< json tag for no-restapi */
#define ENABLE_CLI_TAG "cli"        /**< json tag to enable/disable CLI */
#define MODE_TAG "mode"             /**< json tag to set the mode flag */
#define UDS_PATH_TAG "uds_path"     /**< json tag to set the uds path */
#define XSKDEV_API_NAME "xskdev"
#define PKTDEV_API_NAME "pktdev"

#define MAX_STRLEN_SIZE 16
#define CNDP_MAX_BURST 256

typedef enum { UNKNOWN_PKT_API, XSKDEV_PKT_API, PKTDEV_PKT_API } pkt_api_t;

// Bess PacketPool
typedef std::array<bess::PacketPool *, RTE_MAX_NUMA_NODES> CndpPacketPoolArray;
typedef std::map<std::string, CndpPacketPoolArray *> CndpPacketPoolMap;

// Forward declaration.
class CndpSingleton;
struct fwd_port;

/// This driver binds a port to a device using CNDP/DPDK.
class CndpPort final : public Port {
 public:
  /*!
   * Initialize the CNDP port.
   *
   * PARAMETERS:
   * * string jsonc_file : CNDP Jsonc configuration file.
   * * uint32 lport_index : CNDP lport in jsonc file used to send/recv n/w pkts.
   *
   * EXPECTS:
   * * Must specify both jsonc_file and lport_index.
   */
  CommandResponse Init(const bess::pb::CndpPortArg &arg);

  /*!
   * Reset the port.
   */
  void DeInit() override;

  /*!
   * Sends packets out on the device.
   *
   * PARAMETERS:
   * * queue_t quid : qid is configured via jsonc and this argument is ignored
   * * for now. This value is expected to be zero.
   * * bess::Packet ** pkts : packets to transmit.
   * * int cnt : number of packets in pkts to transmit.
   *
   * EXPECTS:
   * * Only call this after calling Init with a device.
   * * Don't call this after calling DeInit().
   *
   * RETURNS:
   * * Total number of packets sent (<=cnt).
   */
  int SendPackets(queue_t qid, bess::Packet **pkts, int cnt) override;

  /*!
   * Receives packets from the device.
   *
   * PARAMETERS:
   * * queue_t quid : qid is configured via jsonc and this argument is ignored
   * * for now. This value is expected to be zero.
   * * bess::Packet **pkts : buffer to store received packets in to.
   * * int cnt : max number of packets to pull.
   *
   * EXPECTS:
   * * Only call this after calling Init with a device.
   * * Don't call this after calling DeInit().
   *
   * RETURNS:
   * * Total number of packets received (<=cnt)
   */
  int RecvPackets(queue_t qid, bess::Packet **pkts, int cnt) override;

  /*!
   * Copies CNDP port statistics into queue_stats datastructure (see port.h).
   *
   * PARAMETERS:
   * * bool reset : if true, reset CNDP local statistics and return (do not
   * collect stats).
   */
  void CollectStats(bool reset) override;

  uint64_t GetFlags() const override {
    return DRIVER_FLAG_SELF_INC_STATS | DRIVER_FLAG_SELF_OUT_STATS;
  }

  /*!
   * Get any placement constraints that need to be met when receiving from this
   * port.
   */
  placement_constraint GetNodePlacementConstraint() const override;

 private:
  // CNDP singleton instance.
  CndpSingleton *cndp_instance_;

  // jsonc file used for configuring CNDP.
  std::string jsonc_file_;

  // CNDP lport index
  uint32_t lport_index_;

  // CNDP lport.
  jcfg_lport_t *lport_;

  // CNDP fwd port.
  fwd_port *lport_fport_;

  // Bess Packet array.
  std::array<bess::Packet *, bess::PacketBatch::kMaxBurst> pkt_recv_vector_;

  // CNDP stats.
  lport_stats_t cndp_stats_;

  // CPU socket id for this lport.
  int lport_socket_id_;

  bool ReplenishRecvVector(int cnt);
  void FreeRecvVector();
  void CndpStats(bool reset);
  uint16_t XskdevRecvPackets(struct fwd_port *fport, bess::Packet **pkts,
                             int cnt);
  uint16_t PktdevRecvPackets(struct fwd_port *fport, bess::Packet **pkts,
                             int cnt);
  uint16_t PktdevSendPackets(struct fwd_port *fport, bess::Packet **pkts,
                             int cnt);
  uint16_t XskdevSendPackets(struct fwd_port *fport, bess::Packet **pkts,
                             int cnt);
};

struct fwd_port {
  union {
    xskdev_info_t *xsk; /**< XSKDEV information pointer */
    int lport;          /**< PKTDEV lport id */
  };
  union {
    bess::PacketPool *bess_pool;      /**< BESS pool pointer */
    pktmbuf_t *mbufs[CNDP_MAX_BURST]; /**< TX/RX mbufs array */
  };
  pkt_api_t pkt_api; /**< The packet API mode */
  uint64_t ipackets; /**< previous rx packets */
  uint64_t opackets; /**< previous tx packets */
  uint64_t ibytes;   /**< previous rx bytes */
  uint64_t obytes;   /**< previous tx bytes */
};

class CndpSingleton {
 public:
  static CndpSingleton &GetInstance(const std::string &jsonc_file);
  CndpSingleton(CndpSingleton const &) = delete;
  void operator=(CndpSingleton const &) = delete;
  void Quit();
  bool IsConfigured();
  jcfg_lport_t *GetLportFromIndex(int index);
  int GetNumLports();
  static int CndpRegisterThread(const std::string &register_name);
  fwd_port *GetFwdPort(const jcfg_lport_t *lport);
  static int GetSocketId(char *ifname);
  static int GetSocketId(uint32_t lport_id);
  static bess::PacketPool *GetCndpPacketPool(std::string umem_name,
                                             int socket_id);

 private:
  std::string jsonc_file_;
  bool configured_;
  static CndpPacketPoolMap cndp_packet_pool_;
  static const size_t kDefaultCapacity = (1 << 17) - 1;  // 128k - 1

  struct app_options {
    bool no_metrics; /**< Enable metrics*/
    bool no_restapi; /**< Enable REST API*/
    bool cli;        /**< Enable Cli*/
    char *mode;      /**< Application mode*/
    char *pkt_api;   /**< The pkt API mode */
  };

  struct fwd_info {
    jcfg_info_t *jinfo;      /**< JSON-C configuration */
    uint32_t flags;          /**< Application set of flags */
    volatile int quit;       /**< flags to start and stop the application */
    struct app_options opts; /**< Application options*/
    pkt_api_t pkt_api;       /**< The packet API mode */
    uds_info_t *xdp_uds;     /**< UDS to get xsk map fd from */
  };

  struct fwd_info fwd_;

  CndpSingleton(const std::string &jsonc_file);
  int ParseFile(const char *json_file, struct fwd_info *fwd);
  static pkt_api_t GetPktApi(const char *type);
  static int CreateXskdevSocket(jcfg_umem_t *umem, jcfg_lport_t *lport,
                                struct fwd_port *pd, struct fwd_info *f);
  static int CreatePktdevSocket(jcfg_umem_t *umem, jcfg_lport_t *lport,
                                struct fwd_port *pd, struct fwd_info *f);
  static int JcfgProcessCallback(jcfg_info_t *j __cne_unused, void *_obj,
                                 void *arg, int idx __cne_unused);
  static int CndpQuit(jcfg_info_t *j __cne_unused, void *obj, void *arg,
                      int idx __cne_unused);
  static uintptr_t GetUmemBaseAddr(struct rte_mempool *mp);
  static uintptr_t GetPageAlignedAddr(uintptr_t mem_addr, uint64_t *align);
  static int CndpBufAlloc(void *arg, void **bufs, uint16_t nb_bufs);
  static void CndpBufFree(void *arg, void **bufs, uint16_t nb_bufs);
  static void CndpBufSetDataLen(void *mb, int len);
  static void CndpBufSetLen(void *mb, int len);
  static void CndpBufSetData(void *mb, uint64_t off);
  static uint64_t CndpBufGetData(void *mb);
  static uint16_t CndpBufGetDataLen(void *mb);
  static uint64_t CndpBufGetAddr(void *mb);
  static void **CndpBufIncPtr(void **mbs);
  static void CndpBufReset(void *mb, uint32_t buf_len, size_t headroom);
  static bool CreateCndpPacketPool(std::string umem_name,
                                   size_t capacity = kDefaultCapacity);
  static bool CreatePktmbufPool(jcfg_umem_t *umem, jcfg_info_t *j);
};

#endif  // BESS_DRIVERS_CNDP_H_
