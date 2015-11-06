#!/usr/bin/python3
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
import argparse
import logging
import threading
import time

# SCION
from endhost.sciond import SCIONDaemon
from lib.defines import GEN_PATH, SCION_UDP_EH_DATA_PORT
from lib.log import init_logging
from lib.main import main_wrapper
from lib.packet.ext.traceroute import TracerouteExt
from lib.packet.host_addr import haddr_parse_interface
from lib.packet.packet_base import PayloadRaw
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scion_udp import SCIONUDPHeader
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.util import handle_signals

TOUT = 10  # How long wait for response.


def client(c_addr, s_addr):
    """
    Simple client
    """
    conf_dir = "%s/ISD%d/AD%d/endhost" % (GEN_PATH, c_addr.isd_id, c_addr.ad_id)
    # Start SCIONDaemon
    sd = SCIONDaemon.start(conf_dir, c_addr.host_addr)
    logging.info("CLI: Sending PATH request for (%d, %d)",
                 s_addr.isd_id, s_addr.ad_id)
    # Open a socket for incomming DATA traffic
    sock = UDPSocket(bind=(str(c_addr.host_addr), 0, "Client"),
                     addr_type=c_addr.host_addr.TYPE)
    # Get paths to server through function call
    paths = sd.get_paths(s_addr.isd_id, s_addr.ad_id)
    assert paths
    # Get a first path
    path = paths[0]
    # Determine number of border routers on path in single direction
    routers_no = (path.get_ad_hops() - 1) * 2
    # Number of router for round-trip (return path is symmetric)
    routers_no *= 2
    # Create empty Traceroute extensions with allocated space
    ext = TracerouteExt.from_values(routers_no)
    # Set payload
    payload = PayloadRaw(b"request to server")
    # Create a SCION packet with the extensions
    cmn_hdr, addr_hdr = build_base_hdrs(c_addr, s_addr)
    udp_hdr = SCIONUDPHeader.from_values(
        c_addr, sock.port, s_addr, SCION_UDP_EH_DATA_PORT, payload,
    )
    spkt = SCIONL4Packet.from_values(cmn_hdr, addr_hdr, path, [ext], udp_hdr,
                                     payload)
    # Determine first hop (i.e., local address of border router)
    (next_hop, port) = sd.get_first_hop(spkt)
    logging.info("CLI: Sending packet:\n%s\nFirst hop: %s:%s",
                 spkt, next_hop, port)
    # Send packet to first hop (it is sent through SCIONDaemon)
    sd.send(spkt, next_hop, port)
    # Waiting for a response
    raw, _ = sock.recv()
    logging.info('CLI: Received response:\n%s', SCIONL4Packet(raw))
    logging.info("CLI: leaving.")
    sock.close()


def server(addr):
    """
    Simple server.
    """
    conf_dir = "%s/ISD%d/AD%d/endhost" % (GEN_PATH, addr.isd_id, addr.ad_id)
    # Start SCIONDaemon
    sd = SCIONDaemon.start(conf_dir, addr.host_addr)
    # Open a socket for incomming DATA traffic
    sock = UDPSocket(
        bind=(str(addr.host_addr), SCION_UDP_EH_DATA_PORT, "Server"),
        addr_type=addr.host_addr.TYPE
    )
    # Waiting for a request
    raw, _ = sock.recv()
    # Request received, instantiating SCION packet
    spkt = SCIONL4Packet(raw)
    logging.info('SRV: received: %s', spkt)
    if spkt.get_payload() == PayloadRaw(b"request to server"):
        logging.info('SRV: request received, sending response.')
        # Reverse the packet
        spkt.reverse()
        # Setting payload
        spkt.set_payload(PayloadRaw(b"response"))
        # Determine first hop (i.e., local address of border router)
        (next_hop, port) = sd.get_first_hop(spkt)
        # Send packet to first hop (it is sent through SCIONDaemon)
        sd.send(spkt, next_hop, port)
    logging.info("SRV: Leaving server.")
    sock.close()


def main():
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--client', help='Client address')
    parser.add_argument('-s', '--server', help='Server address')
    parser.add_argument('-m', '--mininet', action='store_true',
                        help="Running under mininet")
    parser.add_argument('cli_ad', nargs='?', help='Client isd,ad',
                        default="1,19")
    parser.add_argument('srv_ad', nargs='?', help='Server isd,ad',
                        default="2,26")
    args = parser.parse_args()
    init_logging("logs/c2s_extn.log", console=True)

    if not args.client:
        args.client = "169.254.0.2" if args.mininet else "127.0.0.2"
    if not args.server:
        args.server = "169.254.0.3" if args.mininet else "127.0.0.3"

    srv_isd, srv_ad = map(int, args.srv_ad.split(","))
    srv_addr = SCIONAddr.from_values(srv_isd, srv_ad,
                                     haddr_parse_interface(args.server))
    threading.Thread(
        target=thread_safety_net, args=(server, srv_addr),
        name="C2S_extn.server", daemon=True).start()
    time.sleep(0.5)

    cli_isd, cli_ad = map(int, args.cli_ad.split(","))
    cli_addr = SCIONAddr.from_values(cli_isd, cli_ad,
                                     haddr_parse_interface(args.client))
    t_client = threading.Thread(
        target=thread_safety_net, args=(
            client, cli_addr, srv_addr,
        ), name="C2S_extn.client", daemon=True)
    t_client.start()
    t_client.join()

if __name__ == "__main__":
    main_wrapper(main)
