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
import time

# SCION
from endhost.sciond import SCIONDaemon
from lib.defines import GEN_PATH, SIBRA_TICK, SIBRA_MAX_IDX
from lib.log import init_logging
from lib.main import main_wrapper
from lib.packet.ext_util import find_ext_hdr
from lib.packet.host_addr import haddr_parse_interface
from lib.packet.packet_base import PayloadRaw
from lib.packet.path import EmptyPath
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scion_udp import SCIONUDPHeader
from lib.sibra.ext.steady import SibraExtSteady
from lib.sibra.ext.info import ResvInfoSteady
from lib.sibra.util import BWSnapshot
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.types import ExtensionClass
from lib.util import handle_signals, SCIONTime

TOUT = 10  # How long wait for response.
RESV_LEN = SIBRA_TICK


def start_sciond(isd, ad, addr):
    conf_dir = "%s/ISD%d/AD%d/endhost" % (GEN_PATH, isd, ad)
    return SCIONDaemon.start(conf_dir, haddr_parse_interface(addr))


def get_up_path(sd, isd):
    logging.info("Sending up PATH request")
    for _ in range(3):
        paths = sd.get_paths(isd, 0)
        if paths:
            break
        logging.info("Failed to get up path, trying again")
    else:
        logging.error("Unable to get an up path, giving up")
        sys.exit(1)
    return paths[0]


class _Base(object):
    def __init__(self, addr, sd, finished):
        self.addr = addr
        self.sd = sd
        self.finished = finished
        self.sock = UDPSocket(
            bind=(str(self.addr.host_addr), 0, self.NAME),
            addr_type=self.addr.host_addr.TYPE)
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
        spkt = self.setup_conn(s_addr, s_port, path)
        if not spkt:
            self.finished.set()
            return
        spkt.path = EmptyPath()
        start = SCIONTime.get_time()
        i = 0
        while SCIONTime.get_time() < start + 180:
            if self.finished.is_set():
                break
            spkt.reverse()
            if not self.handle_renewal(spkt):
                break
            pld = PayloadRaw(("ping %d" % i).encode("ascii"))
            spkt.set_payload(pld)
            self.send(spkt)
            spkt = self.listen()
            if not spkt:
                break
            i += 1
            time.sleep(1.0)
        logging.info("Finished")
        self.finished.set()

    def setup_conn(self, s_addr, s_port, path):
        bwsnap = BWSnapshot(25 * 1024, 15 * 1024)
        for i in range(3):
            sibra_ext = self.create_ext(path.get_ad_hops(), bwsnap)
            spkt = self.create_pkt(s_addr, s_port, path, sibra_ext)
            self.send(spkt)
            spkt = self.listen()
            if not spkt:
                break
            sibra_ext = self.get_ext(spkt)
            if sibra_ext.accepted:
                sibra_ext.switch_resv([sibra_ext.req_block])
                sibra_ext.req_block = None
                return spkt
            bwsnap = sibra_ext.get_min_offer()
        logging.error("Unable to setup connection after 3 tries")
        self.finished.set()

    def create_ext(self, hops, bwsnap):
        resv_req = ResvInfoSteady.from_values(
            SCIONTime.get_time() + RESV_LEN, bwsnap)
        return SibraExtSteady.from_values(
            self.addr.get_isd_ad(), resv_req, hops)

    def create_pkt(self, s_addr, port, path, ext):
        cmn_hdr, addr_hdr = build_base_hdrs(self.addr, s_addr)
        udp_hdr = SCIONUDPHeader.from_values(
            self.addr, self.sock.port, s_addr, port)
        return SCIONL4Packet.from_values(cmn_hdr, addr_hdr, path,
                                         [ext], udp_hdr)

    def get_ext(self, spkt):
        return find_ext_hdr(spkt, ExtensionClass.HOP_BY_HOP,
                            SibraExtSteady.EXT_TYPE)

    def handle_renewal(self, spkt):
        sibra_ext = self.get_ext(spkt)
        act_info = sibra_ext.active_blocks[0].info
        if sibra_ext.req_block and sibra_ext.accepted:
            req_info = sibra_ext.req_block.info
            logging.debug("Renewal succeded")
            self.blocks.append(sibra_ext.req_block)
            new_idx = (req_info.index + 1) % SIBRA_MAX_IDX
            next_cls = req_info.bw.copy()
            # next_cls.reverse()
            bwsnap = next_cls.to_snap()
            bwsnap.fwd += 2
            bwsnap.rev += 2
        elif sibra_ext.req_block:
            sibra_ext.req_block.info
            logging.debug("Renewal denied")
            new_idx = (sibra_ext.req_block.info.index + 1) % SIBRA_MAX_IDX
            bwsnap = sibra_ext.get_min_offer()
        else:
            # Fresh start
            new_idx = (act_info.index + 1) % SIBRA_MAX_IDX
            next_cls = act_info.bw.copy()
            # next_cls.reverse()
            bwsnap = next_cls.to_snap()

        now = SCIONTime.get_time()
        if now > act_info.exp_ts() and not self.blocks:
            logging.error("Current block expired, and no "
                          "renewal blocks available to switch to")
            return False
        if now + SIBRA_TICK > act_info.exp_ts() and self.blocks:
            block = self.blocks.pop()
            self.blocks = []
            logging.debug("Switching resv: %s", block.info)
            sibra_ext.switch_resv([block])

        resv_req = ResvInfoSteady.from_values(now + RESV_LEN, bwsnap, new_idx)
        sibra_ext.renew(resv_req)
        return True


def main():
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--mininet', action='store_true',
                        help="Running under mininet")
    parser.add_argument('cli_ad', nargs='?', help='Client isd,ad',
                        default="1,13")
    args = parser.parse_args()
    init_logging("logs/sibra_ext", console_level=logging.DEBUG)

    c_addr = "169.254.0.2" if args.mininet else "127.0.0.2"
    s_addr = "169.254.0.3" if args.mininet else "127.0.0.3"
    cli_isd, cli_ad = map(int, args.cli_ad.split(","))
    cli_sd = start_sciond(cli_isd, cli_ad, c_addr)
    up_path = get_up_path(cli_sd, cli_isd)
    core = up_path.interfaces[-1][0]
    srv_sd = start_sciond(core.isd, core.ad, s_addr)

    srv_addr = SCIONAddr.from_values(
        core.isd, core.ad, haddr_parse_interface(s_addr))
    cli_addr = SCIONAddr.from_values(
        cli_isd, cli_ad, haddr_parse_interface(c_addr))
    finished = threading.Event()
    server = Server(srv_addr, srv_sd, finished)
    client = Client(cli_addr, cli_sd, finished)
    threading.Thread(target=thread_safety_net, args=(server.run,), daemon=True,
                     name="SibraExtTest.server").start()
    threading.Thread(
        target=thread_safety_net, name="SibraExtTest.client", daemon=True,
        args=(client.run, srv_addr, server.sock.port, up_path,)
    ).start()
    finished.wait()

if __name__ == "__main__":
    main_wrapper(main)
