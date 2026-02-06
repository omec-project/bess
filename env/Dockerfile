# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-present Open Networking Foundation
# Copyright 2019-present Intel Corporation
# vim: syntax=dockerfile

# Build stage: Install all build dependencies and compile from source
FROM ubuntu:22.04@sha256:104ae83764a5119017b8e8d6218fa0832b09df65aae7d5a6de29a85d813da2fb AS builder

ENV DEBIAN_FRONTEND=noninteractive

COPY env/build-dep.yml /tmp/
COPY env/kmod.yml /tmp/
COPY env/ci.yml /tmp/
COPY env/cndp.yml /tmp/
COPY env/requirements-dev.txt /tmp/

# Install build dependencies and compile everything
RUN apt-get update && \
    apt-get install -y \
    --no-install-recommends \
    ansible \
    curl && \
    ansible-playbook /tmp/cndp.yml -i "localhost," -c local && \
    ansible-playbook /tmp/ci.yml -i "localhost," -c local && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Runtime stage: Only runtime libraries
FROM ubuntu:22.04@sha256:104ae83764a5119017b8e8d6218fa0832b09df65aae7d5a6de29a85d813da2fb

ENV DEBIAN_FRONTEND=noninteractive

# Set CNDP PKG_CONFIG_PATH
ENV PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/pkgconfig

# Install only runtime libraries (no -dev packages)
RUN apt-get update && \
    apt-get install -y \
    --no-install-recommends \
    ca-certificates \
    python3 \
    python3-pip \
    pkg-config \
    libelf1 \
    libbsd0 \
    libjson-c5 \
    libnl-3-200 \
    libnl-cli-3-200 \
    libnuma1 \
    libpcap0.8 \
    libunwind8 \
    liblzma5 \
    zlib1g \
    libssl3 \
    libgflags2.2 \
    libgoogle-glog0v5 \
    libgtest-dev \
    libc-ares2 \
    libbenchmark1 \
    ethtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy Python dependencies
COPY env/requirements.txt /tmp/
RUN pip3 install --no-cache-dir --require-hashes -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Copy compiled binaries from builder
COPY --from=builder /usr/local/bin/protoc /usr/local/bin/
COPY --from=builder /usr/local/bin/grpc_* /usr/local/bin/
COPY --from=builder /usr/bin/cndpfwd /usr/bin/
COPY --from=builder /usr/bin/prometheus /usr/bin/

# Copy compiled libraries from builder
COPY --from=builder /usr/local/lib/libproto* /usr/local/lib/
COPY --from=builder /usr/local/lib/libgrpc* /usr/local/lib/
COPY --from=builder /usr/local/lib/libgpr* /usr/local/lib/
COPY --from=builder /usr/local/lib/libabsl* /usr/local/lib/
COPY --from=builder /usr/local/lib/pkgconfig/ /usr/local/lib/pkgconfig/
COPY --from=builder /usr/lib/libxdp* /usr/lib/
COPY --from=builder /usr/lib/libcne* /usr/lib/
COPY --from=builder /usr/lib/libcndp* /usr/lib/
COPY --from=builder /usr/lib/libtun* /usr/lib/
COPY --from=builder /usr/lib/libpmd* /usr/lib/
COPY --from=builder /usr/lib/pkgconfig/ /usr/lib/pkgconfig/

# Copy headers from builder
COPY --from=builder /usr/local/include/google/ /usr/local/include/google/
COPY --from=builder /usr/local/include/grpc* /usr/local/include/
COPY --from=builder /usr/local/include/absl/ /usr/local/include/absl/
COPY --from=builder /usr/local/include/cndp/ /usr/local/include/cndp/
COPY --from=builder /usr/include/xdp/ /usr/include/xdp/

# Update dynamic linker cache
RUN ldconfig
