# Copyright 2015 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`cli_srv_ext_test` --- SCION client-server test with an extension
======================================================================
"""
# Stdlib
import logging
import socket
import threading
import time
from ipaddress import IPv4Address

# SCION
from endhost.sciond import SCIONDaemon
from lib.defines import SCION_BUFLEN, SCION_UDP_EH_DATA_PORT
from lib.packet.ext.traceroute import TracerouteExt
from lib.packet.scion import SCIONPacket
from lib.packet.scion_addr import SCIONAddr

TOUT = 10  # How long wait for response.
CLI_ISD = 1
CLI_AD = 19
CLI_IP = "127.1.19.254"
SRV_ISD = 2
SRV_AD = 26
SRV_IP = "127.1.26.254"


def client():
    """
    Simple client
    """
    topo_file = ("../../topology/ISD%d/topologies/ISD:%d-AD:%d.json" %
                 (CLI_ISD, CLI_ISD, CLI_AD))
    # Start SCIONDaemon
    sd = SCIONDaemon.start(IPv4Address(CLI_IP), topo_file)
    print("CLI: Sending PATH request for (%d, %d)" % (SRV_ISD, SRV_AD))
    # Get paths to server through function call
    paths = sd.get_paths(SRV_ISD, SRV_AD)
    assert paths
    # Get a first path
    path = paths[0]
    # Determine number of border routers on path
    routers_no = (path.get_ad_hops() - 1) * 2
    # Create a SCION address to the destination
    dst = SCIONAddr.from_values(SRV_ISD, SRV_AD, IPv4Address(SRV_IP))
    # Set payload
    payload = b"request to server"
    # Create empty Traceroute extensions
    ext = TracerouteExt.from_values(routers_no)
    # Create a SCION packet with the extensions
    spkt = SCIONPacket.from_values(sd.addr, dst, payload, path, ext_hdrs=[ext])
    # Determine first hop (i.e., local address of border router)
    (next_hop, port) = sd.get_first_hop(spkt)
    print("CLI: Sending packet: %s\nFirst hop: %s:%s" % (spkt, next_hop, port))
    # Send packet to first hop (it is sent through SCIONDaemon)
    sd.send(spkt, next_hop, port)
    # Open a socket for incomming DATA traffic
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((CLI_IP, SCION_UDP_EH_DATA_PORT))
    # Waiting for a response
    raw, _ = sock.recvfrom(SCION_BUFLEN)
    print('\n\nCLI: Received response:\n%s' % SCIONPacket(raw))
    print("CLI: leaving.")
    sock.close()
    sd.clean()


def server():
    """
    Simple server.
    """
    topo_file = ("../../topology/ISD%d/topologies/ISD:%d-AD:%d.json" %
                 (SRV_ISD, SRV_ISD, SRV_AD))
    # Start SCIONDaemon
    sd = SCIONDaemon.start(IPv4Address(SRV_IP), topo_file)
    # Open a socket for incomming DATA traffic
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SRV_IP, SCION_UDP_EH_DATA_PORT))
    # Waiting for a request
    raw, _ = sock.recvfrom(SCION_BUFLEN)
    # Request received, instantiating SCION packet
    spkt = SCIONPacket(raw)
    print('SRV: received: %s', spkt)
    if spkt.payload == b"request to server":
        print('SRV: request received, sending response.')
        # Reverse the packet
        spkt.hdr.reverse()
        # Setting payload
        spkt.payload = b"response"
        # Determine first hop (i.e., local address of border router)
        (next_hop, port) = sd.get_first_hop(spkt)
        # Send packet to first hop (it is sent through SCIONDaemon)
        sd.send(spkt, next_hop, port)
    print("SRV: Leaving server.")
    sock.close()
    sd.clean()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    # if len(sys.argv) == 3:
    #     isd, ad = sys.argv[1].split(',')
    #     sources = [(int(isd), int(ad))]
    #     isd, ad = sys.argv[2].split(',')
    #     destinations = [(int(isd), int(ad))]
    # TestSCIONDaemon().test(sources, destinations)
    threading.Thread(target=server).start()
    time.sleep(0.5)
    threading.Thread(target=client).start()
