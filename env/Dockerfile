# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-present Open Networking Foundation
# Copyright 2019-present Intel Corporation
# vim: syntax=dockerfile

# Go build stage: compile the CNDP Prometheus metrics exporter
FROM golang:1.26.0-bookworm@sha256:eae3cdfa040d0786510a5959d36a836978724d03b34a166ba2e0e198baac9196 AS prometheus-build
RUN git clone --depth 1 --branch v24.07.0 \
      https://github.com/CloudNativeDataPlane/cndp.git /tmp/cndp
WORKDIR /tmp/cndp/lang/go/stats/prometheus
RUN go build -o /prometheus prometheus.go

# Build stage: Install all build dependencies and compile from source
FROM ubuntu:24.04@sha256:d1e2e92c075e5ca139d51a140fff46f84315c0fdce203eab2807c7e495eff4f9 AS builder

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

ARG CPU=haswell
ARG MAKEFLAGS
ENV CPU=${CPU} MAKEFLAGS=${MAKEFLAGS} PLUGINS_DIR=plugins
ENV PKG_CONFIG_PATH=/usr/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/local/lib/pkgconfig:/usr/local/lib/x86_64-linux-gnu/pkgconfig
ENV BESS_LINK_DYNAMIC=1

WORKDIR /bess
COPY . .
RUN cp -a protobuf /protobuf && \
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
    strip /bin/bessd && \
    mkdir -p /bin/modules && \
    cp core/modules/*.so /bin/modules && \
    mkdir -p /opt/bess && \
    cp -r bessctl pybess /opt/bess

# Collect only the shared libraries needed at runtime into a staging directory.
# ldd finds direct/transitive deps of bessd; we also include DPDK PMD drivers
# (loaded via dlopen at runtime, invisible to ldd) and DPDK bus/mempool drivers.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN mkdir -p /staging/lib && \
    for lib in $(ldd /bin/bessd 2>/dev/null | grep '/usr/local/lib' | awk '{print $3}'); do \
      cp -a "${lib}"* /staging/lib/ 2>/dev/null || true; \
    done && \
    for pat in af_packet af_xdp vhost virtio mlx5 pcap net_ring net_tap bus mempool_ring common_mlx5; do \
      cp -aL /usr/local/lib/x86_64-linux-gnu/librte_*${pat}*.so* /staging/lib/ 2>/dev/null || true; \
    done && \
    cp -aL /usr/local/lib/x86_64-linux-gnu/libcne_*.so* /staging/lib/ 2>/dev/null || true && \
    cp -aL /usr/local/lib/x86_64-linux-gnu/libcndp.so* /staging/lib/ 2>/dev/null || true

# Default target: pre-built BESS image with runtime deps and compiled artifacts.
FROM ubuntu:24.04@sha256:d1e2e92c075e5ca139d51a140fff46f84315c0fdce203eab2807c7e495eff4f9

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

# Copy CNDP binary (meson installs to /usr/local/bin/)
COPY --from=bess-build /usr/local/bin/cndpfwd /usr/bin/
# Copy prometheus metrics exporter built in the dedicated Go stage
COPY --from=prometheus-build /prometheus /usr/local/bin/prometheus

# Copy protoc for downstream protobuf generation (go-pb, py-pb)
# System package installs to /usr/bin/
COPY --from=bess-build /usr/bin/protoc /usr/local/bin/

# Copy only the runtime-needed shared libraries (CNDP + DPDK core + select PMDs)
COPY --from=bess-build /staging/lib/ /usr/local/lib/x86_64-linux-gnu/

# Copy protobuf include files needed by protoc (system package path)
COPY --from=bess-build /usr/include/google/protobuf /usr/local/include/google/protobuf

# Ensure the dynamic linker can find libraries in /usr/local/lib/x86_64-linux-gnu
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/usr-local.conf && \
    echo "/usr/local/lib/x86_64-linux-gnu" >> /etc/ld.so.conf.d/usr-local.conf && \
    ldconfig
