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

# Set PATH to include /usr/local/bin where pip installs executables
ENV PATH=/usr/local/bin:${PATH}

# Set PKG_CONFIG_PATH to include both system and local packages
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/lib64/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/pkgconfig

# Install runtime libraries and development headers needed for BESS compilation
RUN apt-get update && \
    apt-get install -y \
    --no-install-recommends \
    ca-certificates \
    curl \
    git \
    python3 \
    python3-pip \
    pkg-config \
    build-essential \
    libelf-dev \
    libbsd-dev \
    libjson-c-dev \
    libnl-3-dev \
    libnl-cli-3-dev \
    libnl-route-3-dev \
    libnuma-dev \
    libpcap-dev \
    libunwind8 \
    liblzma5 \
    zlib1g \
    libssl3 \
    libgflags-dev \
    libgoogle-glog-dev \
    libgtest-dev \
    libc-ares2 \
    libbenchmark-dev \
    libbpf-dev \
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
COPY --from=builder /usr/local/lib/libutf8* /usr/local/lib/
COPY --from=builder /usr/local/lib/libupb* /usr/local/lib/
COPY --from=builder /usr/local/lib/libre2* /usr/local/lib/
COPY --from=builder /usr/local/lib/libaddress_sorting* /usr/local/lib/
COPY --from=builder /usr/local/lib/pkgconfig/ /usr/local/lib/pkgconfig/
COPY --from=builder /usr/lib/libxdp* /usr/lib/
COPY --from=builder /usr/lib/libcne* /usr/lib/
COPY --from=builder /usr/lib/libcndp* /usr/lib/
COPY --from=builder /usr/lib/libtun* /usr/lib/
COPY --from=builder /usr/lib/libpmd* /usr/lib/
COPY --from=builder /usr/lib/pkgconfig/ /usr/lib/pkgconfig/

# Copy headers from builder
COPY --from=builder /usr/local/include/google/ /usr/local/include/google/
COPY --from=builder /usr/local/include/grpc/ /usr/local/include/grpc/
COPY --from=builder /usr/local/include/grpc++/ /usr/local/include/grpc++/
COPY --from=builder /usr/local/include/grpcpp/ /usr/local/include/grpcpp/
COPY --from=builder /usr/local/include/absl/ /usr/local/include/absl/
COPY --from=builder /usr/local/include/cndp/ /usr/local/include/cndp/
COPY --from=builder /usr/include/xdp/ /usr/include/xdp/

# Symlink CNDP headers to make them accessible without cndp prefix
# This allows #include <cne_common.h>, #include <jcfg.h> and others to work
WORKDIR /usr/local/include
RUN for dir in cndp/*/; do \
      if [ -d "$dir" ]; then \
        ln -sf "$dir"* . 2>/dev/null || true; \
      fi; \
    done && \
    ln -sf cndp/*.h . 2>/dev/null || true

# Reset working directory to root
WORKDIR /

# Update dynamic linker cache
RUN ldconfig
