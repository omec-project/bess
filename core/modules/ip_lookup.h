// Copyright (c) 2014-2016, The Regents of the University of California.
// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifndef BESS_MODULES_IPLOOKUP_H_
#define BESS_MODULES_IPLOOKUP_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/endian.h"
#include <rte_version.h>
#if RTE_VERSION < RTE_VERSION_NUM(19, 11, 0, 0)
#include <rte_lpm.h>
#else
#define USED(x) (void)(x)
extern "C" {
#include <rte_fib.h>
}
#endif

using bess::utils::be32_t;
using ParsedPrefix = std::tuple<int, std::string, be32_t>;

class IPLookup final : public Module {
 public:
  static const gate_idx_t kNumOGates = MAX_GATES;

  static const Commands cmds;

  IPLookup() : Module(), lpm_(), default_gate_() {
    max_allowed_workers_ = Worker::kMaxWorkers;
  }

  CommandResponse Init(const bess::pb::IPLookupArg &arg);

  void DeInit() override;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandAdd(const bess::pb::IPLookupCommandAddArg &arg);
  CommandResponse CommandDelete(const bess::pb::IPLookupCommandDeleteArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);

 private:
#if RTE_VERSION < RTE_VERSION_NUM(19, 11, 0, 0)
  struct rte_lpm *lpm_;
#else
  struct rte_fib *lpm_;
  struct rte_fib_conf conf;
#endif
  gate_idx_t default_gate_;
  ParsedPrefix ParseIpv4Prefix(const std::string &prefix, uint64_t prefix_len);
};

#endif  // BESS_MODULES_IPLOOKUP_H_
