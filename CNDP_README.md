<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Intel Corporation
-->

# Cloud Native Data Plane (CNDP) BESS Port

Cloud Native Data Plane (CNDP) is a collection of user space libraries for accelerating packet processing for cloud applications. It aims to provide better performance than that of standard network socket interfaces by using an I/O layer primarily built on AF_XDP, an interface that delivers packets directly to user space, bypassing the kernel networking stack. For more details refer https://cndp.io/

CNDP BESS port enables sending/receiving packets to/from network interface using AF-XDP.

Following are the steps required to build BESS CNDP docker image:

### Step 1: Build the BESS CNDP docker image.

> Note: If you are behind a proxy make sure to export/setenv http_proxy and https_proxy

From the top level BESS directory call:

```
$ docker build -t besscndp --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${http_proxy} -f env/Dockerfile-cndp .
```

### Step 2: Run the besscndp docker container

From the top level BESS directory call:

```
$ docker run --network=host -e http_proxy=${http_proxy} -e https_proxy=${http_proxy} --privileged --cap-add=ALL -v /dev/hugepages:/mnt/huge -v /sys/bus/pci/devices:/sys/bus/pci/devices -v /sys/devices/system/node:/sys/devices/system/node -v  /lib/modules:/lib/modules -v /dev:/dev -v /usr/src:/usr/src -it besscndp bash
```

### Step 3: Run example CNDP BESS script

1. Modify the jsonc file in "/build/bess/bessctl/conf/cndp/fwd.jsonc" to use the network device in your system used to send and receive n/w packets.
2. Configure ethtool filter rules as required to send/recv packets via a specified queue id. Ensure that same netdev and queue id is configured in fwd.jsonc file.
3. Run bessctl controller from container shell: `./bessctl/bessctl`
4. From bessctl shell , run bess daemon: `daemon start -log_dir /build/bess/log`
5. Run sample BESS CNDP script: `run cndp/cndpfwd_coreid`. This will run cndpfwd BESS pipeline in a core id specified in "/build/bess/bessctl/conf/cndp/cndpfwd_coreid.bess" script. Before running the script, edit the script to update core in line `bess.add_worker(wid=0, core=28)` to a core id in CPU socket where the network device is attached to get better performance.
6. If everything works fine, then you should see BESS pipeline logs when you run: `monitor pipeline`
