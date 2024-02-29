# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-present Open Networking Foundation
# Copyright 2019 Intel Corporation
# vim: syntax=dockerfile

ARG BASE_IMAGE=ubuntu:focal
# Install CNDP dependencies and build CNDP.
FROM ${BASE_IMAGE} AS cndp-build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    golang \
    libelf-dev \
    meson \
    pkg-config \
    libbsd-dev \
    libjson-c-dev \
    libnl-3-dev \
    libnl-cli-3-dev \
    libnuma-dev \
    libpcap-dev \
    wget \
    llvm-dev \
    libclang-dev \
    clang \
    curl \
    git \
    gcc-multilib \
    llvm \
    lld \
    m4 \
    linux-tools-common \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# Install libxdp
RUN git clone https://github.com/xdp-project/xdp-tools.git
WORKDIR /xdp-tools/
RUN git checkout v1.2.2
RUN ./configure
WORKDIR /xdp-tools/
RUN make -j; PREFIX=/usr make -j install
ENV PKG_CONFIG_PATH=/usr/lib/pkgconfig

# Get CNDP from GitHub
WORKDIR /
RUN git clone https://github.com/CloudNativeDataPlane/cndp.git
WORKDIR /cndp
# Use version of CNDP tested with BESS
RUN git checkout d5ce4b9edc2e7ddb46a61b395deffafaf11a0500
# Build and install CNDP shared libraries
RUN make && make install
# Build and install CNDP static libraries
RUN make static_build=1 rebuild install

# Build the prometheus-metrics app
WORKDIR /cndp/lang/go/stats/prometheus/
RUN go build prometheus.go

FROM ${BASE_IMAGE}

# Install CNDP dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    ethtool \
    libbsd-dev \
    libbpf-dev \
    libelf1 \
    libjson-c-dev \
    libnl-3-dev \
    libnl-cli-3-dev \
    libnuma1 \
    libpcap0.8 \
    pkg-config

# Copy required CNDP libraries, header files, pkg-config and binaries.
COPY --from=cndp-build /cndp/usr/local/bin/cndpfwd /usr/bin/
COPY --from=cndp-build /cndp/usr/local/lib/x86_64-linux-gnu/*.so /usr/lib/
COPY --from=cndp-build /cndp/usr/local/lib/x86_64-linux-gnu/*.a /usr/lib/
COPY --from=cndp-build /cndp/usr/local/include/cndp/ /usr/local/include/cndp/
COPY --from=cndp-build /cndp/usr/local/lib/pkgconfig/libcndp.pc /usr/lib/pkgconfig/
COPY --from=cndp-build /cndp/lang/go/stats/prometheus/prometheus /usr/bin/
COPY --from=cndp-build /usr/lib/libxdp* /usr/lib/
COPY --from=cndp-build /usr/include/xdp/ /usr/include/xdp/

# Set CNDP PKG_CONFIG_PATH
ENV PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/pkgconfig

RUN echo "APT::Install-Recommends false;" >> /etc/apt/apt.conf.d/00recommends && \
	echo "APT::Install-Suggests false;" >> /etc/apt/apt.conf.d/00recommends && \
	echo "APT::AutoRemove::RecommendsImportant false;" >> /etc/apt/apt.conf.d/00recommends && \
	echo "APT::AutoRemove::SuggestsImportant false;" >> /etc/apt/apt.conf.d/00recommends

COPY env/build-dep.yml /tmp/
COPY env/kmod.yml /tmp/
COPY env/ci.yml /tmp/

# Install dependency packages with Ansible
RUN apt-get -q update && \
	apt-get install -y ansible curl && \
        ansible-playbook /tmp/ci.yml -i "localhost," -c local && \
	apt-get purge -y ansible && \
	apt-get autoremove -y && \
	rm -rf /var/lib/apt/lists
RUN update-alternatives --install /usr/local/bin/python python /usr/bin/python3 3
RUN mkdir -p /build/bess

WORKDIR /build/bess
COPY . .

# Build DPDK testpmd (used in bessctl samples)
RUN ./build.py dpdk && \
    cp /build/bess/deps/dpdk-22.11.4/build/app/dpdk-testpmd /usr/local/bin/ && \
    rm -rf /build/bess

ENV CCACHE_DIR=/tmp/ccache
ENV CCACHE_COMPRESS=true
