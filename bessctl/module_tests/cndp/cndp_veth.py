# Copyright (c) 2020-2022 Intel Corporation.
# SPDX-License-Identifier: BSD-3-Clause

from test_utils import *
from pyroute2 import IPRoute
import scapy.all as scapy


def create_veth():
    ipr = IPRoute()
    check_veth_dev1 = ipr.link_lookup(ifname='veth1')
    if len(check_veth_dev1) == 0 :
        ipr.link('add', ifname='veth1', kind='veth', peer='veth2')

    # lookup the index
    veth_dev1 = ipr.link_lookup(ifname='veth1')[0]
    veth_dev2 = ipr.link_lookup(ifname='veth2')[0]

    # bring it down
    ipr.link('set', index=veth_dev1, state='down')
    ipr.link('set', index=veth_dev2, state='down')

    # add primary IP address
    ipr.addr('add', index=veth_dev1,
             address='10.0.0.2', mask=24,
             broadcast='10.0.0.255')
             
    ipr.addr('add', index=veth_dev2,
             address='10.0.0.3', mask=24,
             broadcast='10.0.0.255')         
             
    # bring it up
    ipr.link('set', index=veth_dev1, state='up')
    ipr.link('set', index=veth_dev2, state='up')

def gen_packet():
    eth = scapy.Ether()
    ip = scapy.IP(src='10.0.0.2', dst='10.0.0.3')
    udp = scapy.UDP(sport=10001, dport=10002)
    payload = 'helloworld'
    pkt = eth/ip/udp/payload
    return pkt

def delete_veth():
    ipr = IPRoute()
    check_veth_dev1 = ipr.link_lookup(ifname='veth1')
    if len(check_veth_dev1) > 0 :
        ipr.link('delete', ifname='veth1')


class BessCndpTest(BessModuleTestCase):    

    def test_cndp_veth(self):
        try:
            # Create veth pair [veth1, veth2]. 
            # CNDP port will use veth2 as configured in cndpfwd_veth.bess and conf/cndp/fwd_veth.jsonc.
            create_veth()      
            # Create CNDP BESS port.
            veth_port = CndpPort(jsonc_file='bessctl/conf/cndp/fwd_veth.jsonc', lport_index=0)
            PortInc(port=veth_port) -> MACSwap() -> PortOut(port=veth_port)
        except:
            delete_veth()
            assert False          

        # Send packets to veth2. This will be received by veth1.
        scapy.sendp(gen_packet(),iface="veth2", count=10)

        # Delete veth pair.
        delete_veth()
    

suite = unittest.TestLoader().loadTestsFromTestCase(BessCndpTest)
results = unittest.TextTestRunner(verbosity=2).run(suite)

if results.failures or results.errors:
    sys.exit(1)
