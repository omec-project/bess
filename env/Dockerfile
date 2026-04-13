# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-present Open Networking Foundation
# Copyright 2019-present Intel Corporation
# vim: syntax=dockerfile

# Go build stage: compile the CNDP Prometheus metrics exporter
FROM golang:1.26.2-bookworm@sha256:4f4ab2c90005e7e63cb631f0b4427f05422f241622ee3ec4727cc5febbf83e34 AS prometheus-build
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

# BESS build stage: compile BESS against system DPDK packages
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

# Collect the shared libraries needed at runtime into a staging directory.
# ldd finds direct/transitive deps of bessd from both /usr/local/lib (CNDP)
# and /usr/lib (DPDK from system packages).  We then copy ALL librte_*.so*
# to cover DPDK plugins that EAL dlopen()s at init and their transitive deps
# (e.g. librte_fib, librte_rib) which are invisible to ldd.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN mkdir -p /staging/lib && \
    for lib in $(ldd /bin/bessd 2>/dev/null | grep -E '/usr/(local/)?lib' | awk '{print $3}'); do \
      cp -aL "${lib}"* /staging/lib/ 2>/dev/null || true; \
    done && \
    # Copy ALL DPDK runtime libraries.  DPDK EAL scans and dlopen()s plugins
    # at init time; those plugins may in turn depend on core DPDK libs such as
    # librte_fib, librte_rib, etc. that are invisible to ldd on bessd.
    # Selectively copying only pattern-matched PMDs is fragile and misses
    # these transitive dlopen dependencies.
    cp -aL /usr/lib/x86_64-linux-gnu/librte_*.so* /staging/lib/ 2>/dev/null || true && \
    cp -aL /usr/local/lib/x86_64-linux-gnu/libcne_*.so* /staging/lib/ 2>/dev/null || true && \
    cp -aL /usr/local/lib/x86_64-linux-gnu/libcndp.so* /staging/lib/ 2>/dev/null || true && \
    # Create DPDK plugin directory inside staging so that EAL can dlopen
    # mempool/bus/net drivers at runtime.  bessd passes -d /opt/bess/lib/dpdk-pmds
    # to EAL when this directory exists (see dpdk.cc init_eal).
    mkdir -p /staging/opt/bess/lib/dpdk-pmds && \
    for pat in librte_mempool_ring librte_bus_vdev librte_bus_pci \
               librte_net_af_packet librte_net_af_xdp; do \
      for f in /staging/lib/"${pat}".so*; do \
        [ -f "$f" ] && ln -sf "/usr/local/lib/x86_64-linux-gnu/$(basename "$f")" \
          /staging/opt/bess/lib/dpdk-pmds/; \
      done; \
    done && \
    echo "DPDK PMD staging directory contents:" && \
    ls -la /staging/opt/bess/lib/dpdk-pmds/

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

# Copy only the runtime-needed shared libraries (CNDP + DPDK + select PMDs)
COPY --from=bess-build /staging/lib/ /usr/local/lib/x86_64-linux-gnu/

# Copy protobuf include files needed by protoc (system package path)
COPY --from=bess-build /usr/include/google/protobuf /usr/local/include/google/protobuf

# Copy the DPDK PMD plugin directory from staging.  bessd passes
# -d /opt/bess/lib/dpdk-pmds to EAL when this directory exists.
COPY --from=bess-build /staging/opt/bess/lib/dpdk-pmds/ /opt/bess/lib/dpdk-pmds/
# Re-create symlinks pointing to the final library location
RUN for pat in librte_mempool_ring librte_bus_vdev librte_bus_pci \
               librte_net_af_packet librte_net_af_xdp; do \
      for f in /usr/local/lib/x86_64-linux-gnu/"${pat}".so*; do \
        [ -f "$f" ] && ln -sf "$f" /opt/bess/lib/dpdk-pmds/; \
      done; \
    done && \
    echo "DPDK PMD directory contents:" && \
    ls -la /opt/bess/lib/dpdk-pmds/

# Ensure the dynamic linker can find libraries in /usr/local/lib/x86_64-linux-gnu
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/usr-local.conf && \
    echo "/usr/local/lib/x86_64-linux-gnu" >> /etc/ld.so.conf.d/usr-local.conf && \
    ldconfig
