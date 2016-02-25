#!/usr/bin/python3
# Copyright 2016 ETH Zurich
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
======================================================================
"""
# Stdlib
import argparse
import logging
import socket
import sys
import threading

# SCION
from endhost.sciond import SCIONDaemon
from lib.defines import GEN_PATH, SIBRA_TICK
from lib.flagtypes import PathSegFlags as PSF
from lib.log import init_logging
from lib.main import main_wrapper
from lib.packet.host_addr import haddr_parse_interface
from lib.packet.packet_base import PayloadRaw
from lib.packet.path import EmptyPath
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.packet.scion_udp import SCIONUDPHeader
from lib.sibra.ext.steady import SibraExtSteady
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.util import handle_signals, hex_str

TOUT = 10  # How long wait for response.
RESV_LEN = SIBRA_TICK


def start_sciond(isd_as, addr):
    conf_dir = "%s/ISD%s/AS%s/endhost" % (GEN_PATH, isd_as[0], isd_as[1])
    return SCIONDaemon.start(conf_dir, haddr_parse_interface(addr))


def get_path(sd, dst_ia):
    for _ in range(3):
        paths = sd.get_paths(dst_ia, flags=PSF.SIBRA)
        if paths:
            break
        logging.info("Failed to get up path, trying again")
    else:
        logging.error("Unable to get an up path, giving up")
        sys.exit(1)
    logging.debug("Got path(s):")
    for i, resvs in enumerate(paths):
        logging.debug("  Path %d:", i)
        for id_, resv in resvs:
            logging.debug("    %s: %s", hex_str(id_), resv)
    return paths[0][0]


class _Base(object):
    def __init__(self, addr, sd, finished):
        self.addr = addr
        self.sd = sd
        self.finished = finished
        self.sock = UDPSocket(
            bind=(str(self.addr.host), 0, self.NAME),
            addr_type=self.addr.host.TYPE)
        self.sock.settimeout(5)

    def listen(self):
        try:
            packet = self.sock.recv()[0]
        except socket.timeout:
            logging.error("Listen timeout")
            return None
        spkt = SCIONL4Packet(packet)
        logging.debug("Received:\n%s", spkt)
        return spkt

    def send(self, spkt):
        next_hop, port = self.sd.get_first_hop(spkt)
        if not next_hop or not port:
            logging.critical("Unable to find first hop for\n%s", spkt)
            self.finished.set()
            return
        logging.info("Sending packet:\n%s\nFirst hop: %s:%s",
                     spkt, next_hop, port)
        self.sock.send(spkt.pack(), (str(next_hop), port))


class Server(_Base):
    NAME = "Server"

    def run(self):
        count = 0
        while not self.finished.is_set():
            spkt = self.listen()
            if not spkt:
                self.finished.set()
                break
            spkt.reverse()
            pld = PayloadRaw(("pong %d" % count).encode("ascii"))
            spkt.set_payload(pld)
            self.send(spkt)
            count += 1
        logging.info("Finished")


class Client(_Base):
    NAME = "Client"

    def __init__(self, addr, sd, finished):
        super().__init__(addr, sd, finished)
        self.blocks = []

    def run(self, s_addr, s_port, path):
        spkt = self.create_pkt(s_addr, s_port, path)
        if not spkt:
            self.finished.set()
            return
        pld = PayloadRaw(b"ping")
        spkt.set_payload(pld)
        self.send(spkt)
        self.listen()
        logging.info("Finished")
        self.finished.set()

    def create_pkt(self, s_addr, s_port, path):
        path_id, resv_block = path
        ext = SibraExtSteady.use_from_values(path_id, resv_block)
        cmn_hdr, addr_hdr = build_base_hdrs(self.addr, s_addr)
        udp_hdr = SCIONUDPHeader.from_values(
            self.addr, self.sock.port, s_addr, s_port)
        return SCIONL4Packet.from_values(cmn_hdr, addr_hdr, EmptyPath(),
                                         [ext], udp_hdr)


def main():
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--mininet', action='store_true',
                        help="Running under mininet")
    parser.add_argument('cli_ia', help='Client isd-as',
                        default="1-10")
    parser.add_argument('srv_ia', help='Server isd-as',
                        default="1-13")
    args = parser.parse_args()
    init_logging("logs/sibra_ext", console_level=logging.DEBUG)

    c_addr = "169.254.0.2" if args.mininet else "127.0.0.2"
    cli_ia = ISD_AS(args.cli_ia)
    cli_addr = SCIONAddr.from_values(cli_ia, haddr_parse_interface(c_addr))
    cli_sd = start_sciond(cli_ia, c_addr)

    s_addr = "169.254.0.3" if args.mininet else "127.0.0.3"
    srv_ia = ISD_AS(args.srv_ia)
    srv_addr = SCIONAddr.from_values(srv_ia, haddr_parse_interface(s_addr))
    srv_sd = start_sciond(srv_ia, s_addr)

    path = get_path(cli_sd, srv_ia)
    finished = threading.Event()
    server = Server(srv_addr, srv_sd, finished)
    client = Client(cli_addr, cli_sd, finished)
    threading.Thread(target=thread_safety_net, args=(server.run,), daemon=True,
                     name="SibraExtTest.server").start()
    threading.Thread(
        target=thread_safety_net, name="SibraExtTest.client", daemon=True,
        args=(client.run, srv_addr, server.sock.port, path,)
    ).start()
    finished.wait()

if __name__ == "__main__":
    main_wrapper(main)
