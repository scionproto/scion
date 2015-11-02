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
import logging
import socket
import threading
import time
import sys

# SCION
from endhost.sciond import SCIONDaemon
from lib.defines import GEN_PATH, SCION_BUFLEN, SCION_UDP_EH_DATA_PORT
from lib.log import init_logging, log_exception
from lib.packet.ext.traceroute import TracerouteExt
from lib.packet.host_addr import haddr_parse
from lib.packet.packet_base import PayloadRaw
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scion_udp import SCIONUDPHeader
from lib.thread import thread_safety_net
from lib.util import handle_signals

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
    conf_dir = "%s/ISD%d/AD%d/endhost" % (GEN_PATH, CLI_ISD, CLI_AD)
    # Start SCIONDaemon
    sd = SCIONDaemon.start(conf_dir, haddr_parse("IPV4", CLI_IP))
    logging.info("CLI: Sending PATH request for (%d, %d)", SRV_ISD, SRV_AD)
    # Get paths to server through function call
    paths = sd.get_paths(SRV_ISD, SRV_AD)
    assert paths
    # Get a first path
    path = paths[0]
    # Determine number of border routers on path in single direction
    routers_no = (path.get_ad_hops() - 1) * 2
    # Number of router for round-trip (return path is symmetric)
    routers_no *= 2
    # Create empty Traceroute extensions with allocated space
    ext = TracerouteExt.from_values(routers_no)
    # Create a SCION address to the destination
    dst = SCIONAddr.from_values(SRV_ISD, SRV_AD, haddr_parse("IPV4", SRV_IP))
    # Set payload
    payload = PayloadRaw(b"request to server")
    # Create a SCION packet with the extensions
    cmn_hdr, addr_hdr = build_base_hdrs(sd.addr, dst)
    udp_hdr = SCIONUDPHeader.from_values(
        sd.addr, SCION_UDP_EH_DATA_PORT, dst, SCION_UDP_EH_DATA_PORT, payload)
    spkt = SCIONL4Packet.from_values(cmn_hdr, addr_hdr, path, [ext], udp_hdr,
                                     payload)
    # Determine first hop (i.e., local address of border router)
    (next_hop, port) = sd.get_first_hop(spkt)
    logging.info("CLI: Sending packet:\n%s\nFirst hop: %s:%s",
                 spkt, next_hop, port)
    # Send packet to first hop (it is sent through SCIONDaemon)
    sd.send(spkt, next_hop, port)
    # Open a socket for incomming DATA traffic
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((CLI_IP, SCION_UDP_EH_DATA_PORT))
    # Waiting for a response
    raw, _ = sock.recvfrom(SCION_BUFLEN)
    logging.info('CLI: Received response:\n%s', SCIONL4Packet(raw))
    logging.info("CLI: leaving.")
    sock.close()


def server():
    """
    Simple server.
    """
    conf_dir = "%s/ISD%d/AD%d/endhost" % (GEN_PATH, SRV_ISD, SRV_AD)
    # Start SCIONDaemon
    sd = SCIONDaemon.start(conf_dir, haddr_parse("IPV4", SRV_IP))
    # Open a socket for incomming DATA traffic
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SRV_IP, SCION_UDP_EH_DATA_PORT))
    # Waiting for a request
    raw, _ = sock.recvfrom(SCION_BUFLEN)
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


if __name__ == "__main__":
    init_logging("logs/c2s_extn.log", console=True)
    handle_signals()
    # if len(sys.argv) == 3:
    #     isd, ad = sys.argv[1].split(',')
    #     sources = [(int(isd), int(ad))]
    #     isd, ad = sys.argv[2].split(',')
    #     destinations = [(int(isd), int(ad))]
    # TestSCIONDaemon().test(sources, destinations)
    try:
        threading.Thread(
            target=thread_safety_net, args=(server,),
            name="C2S_extn.server", daemon=True).start()
        time.sleep(0.5)
        t_client = threading.Thread(
            target=thread_safety_net, args=(client,),
            name="C2S_extn.client", daemon=True)
        t_client.start()
        t_client.join()
    except SystemExit:
        logging.info("Exiting")
        raise
    except:
        log_exception("Exception in main process:")
        logging.critical("Exiting")
        sys.exit(1)
