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

# BESS build stage: compile BESS and DPDK from source
FROM builder AS bess-build

# Symlink CNDP headers to make them accessible without cndp prefix
# This allows #include <cne_common.h>, #include <jcfg.h> and others to work
WORKDIR /usr/local/include
RUN for dir in cndp/*/; do \
      if [ -d "$dir" ]; then \
        ln -sf "$dir"* . 2>/dev/null || true; \
      fi; \
    done && \
    ln -sf cndp/*.h . 2>/dev/null || true

ARG CPU=haswell
ARG MAKEFLAGS
ENV CPU=${CPU} MAKEFLAGS=${MAKEFLAGS} PLUGINS_DIR=plugins

WORKDIR /bess
COPY . .
RUN cp -a protobuf /protobuf && \
    ./build.py dpdk && \
    mkdir -p plugins && \
    mv sample_plugin plugins

# Build and copy artifacts
RUN PLUGINS=$(find "$PLUGINS_DIR" -mindepth 1 -maxdepth 1 -type d) && \
    CMD="./build.py bess" && \
    for PLUGIN in $PLUGINS; do \
        CMD="$CMD --plugin \"$PLUGIN\""; \
    done && \
    eval "$CMD" && \
    cp bin/bessd /bin && \
    mkdir -p /bin/modules && \
    cp core/modules/*.so /bin/modules && \
    mkdir -p /opt/bess && \
    cp -r bessctl pybess /opt/bess && \
    cp -r core/pb /pb

# Default target: pre-built BESS image with runtime deps and compiled artifacts.
FROM ubuntu:22.04@sha256:104ae83764a5119017b8e8d6218fa0832b09df65aae7d5a6de29a85d813da2fb

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies via Ansible (shared definition with host installs)
COPY env/runtime-deps.yml /tmp/
COPY env/requirements-run.txt /tmp/
RUN apt-get update && \
    apt-get install -y --no-install-recommends ansible && \
    ansible-playbook /tmp/runtime-deps.yml -i "localhost," -c local && \
    apt-get purge -y ansible && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/runtime-deps.yml /tmp/requirements-run.txt

# Copy compiled BESS artifacts
COPY --from=bess-build /bin/bessd /bin/bessd
COPY --from=bess-build /bin/modules /bin/modules
COPY --from=bess-build /opt/bess /opt/bess
COPY --from=bess-build /protobuf /protobuf
COPY --from=bess-build /bess/protobuf /bess/protobuf
COPY --from=bess-build /pb /pb

# Copy CNDP binary
COPY --from=bess-build /usr/bin/cndpfwd /usr/bin/

# Copy protoc for downstream protobuf generation (go-pb, py-pb)
COPY --from=bess-build /usr/local/bin/protoc /usr/local/bin/

# Copy only shared libraries (no static .a files, no headers)
COPY --from=bess-build /usr/local/lib/x86_64-linux-gnu/*.so* /usr/local/lib/x86_64-linux-gnu/
COPY --from=bess-build /usr/local/lib/libproto*.so* /usr/local/lib/
COPY --from=bess-build /usr/local/lib/libgrpc*.so* /usr/local/lib/
COPY --from=bess-build /usr/local/lib/libgpr*.so* /usr/local/lib/
COPY --from=bess-build /usr/local/lib/libabsl*.so* /usr/local/lib/
COPY --from=bess-build /usr/local/lib/libutf8*.so* /usr/local/lib/
COPY --from=bess-build /usr/local/lib/libupb*.so* /usr/local/lib/
COPY --from=bess-build /usr/local/lib/libre2*.so* /usr/local/lib/
COPY --from=bess-build /usr/local/lib/libaddress_sorting*.so* /usr/local/lib/
COPY --from=bess-build /usr/local/lib/libz.so* /usr/local/lib/
COPY --from=bess-build /usr/lib/libxdp* /usr/lib/
COPY --from=bess-build /usr/lib/libcne* /usr/lib/
COPY --from=bess-build /usr/lib/libcndp* /usr/lib/
COPY --from=bess-build /usr/lib/libtun* /usr/lib/
COPY --from=bess-build /usr/lib/libpmd* /usr/lib/
COPY --from=bess-build /usr/lib/x86_64-linux-gnu/libjson-c.so* /usr/lib/x86_64-linux-gnu/

# Copy protobuf include files needed by protoc
COPY --from=bess-build /usr/local/include/google/protobuf /usr/local/include/google/protobuf

RUN ldconfig
