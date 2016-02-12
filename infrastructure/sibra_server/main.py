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
:mod:`main` --- SIBRA service daemon
=====================================
"""
# Stdlib
import base64
import logging
import threading
from queue import Queue

# SCION
from infrastructure.scion_elem import SCIONElement
from infrastructure.sibra_server.link import Link
from infrastructure.sibra_server.util import find_last_ifid
from lib.defines import PATH_SERVICE, SCION_UDP_PORT, SIBRA_SERVICE
from lib.errors import SCIONServiceLookupError
from lib.packet.ext_util import find_ext_hdr
from lib.packet.scion import PacketType as PT
from lib.sibra.ext.steady import SibraExtSteady
from lib.thread import thread_safety_net
from lib.types import (
    AddrType,
    ExtensionClass,
    PathMgmtType as PMT,
    PathSegmentType as PST,
    PayloadClass,
    SIBRAPayloadType,
)
from lib.util import SCIONTime, get_sig_key_file_path, read_file, sleep_interval
from lib.zookeeper import Zookeeper


class SibraServerBase(SCIONElement):
    """
    Base class for the SIBRA service, which is responsible for managing steady
    paths on all interfaces in the local AS.
    """
    SERVICE_TYPE = SIBRA_SERVICE

    def __init__(self, server_id, conf_dir):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        """
        super().__init__(server_id, conf_dir)
        # Map of interface IDs to Link objects
        self.links = {}
        # List of links for all parent ASes
        self.parents = []
        self.sendq = Queue()
        sig_key_file = get_sig_key_file_path(self.conf_dir)
        self.signing_key = base64.b64decode(read_file(sig_key_file))
        self.PLD_CLASS_MAP = {
            PayloadClass.PATH: {
                PMT.REG: self.handle_path_reg,
            },
            PayloadClass.SIBRA: {SIBRAPayloadType.EMPTY:
                                 self.handle_sibra_pkt},
        }
        self._find_links()
        name_addrs = "\0".join([self.id, str(SCION_UDP_PORT),
                                str(self.addr.host)])
        self.zk = Zookeeper(self.addr.isd_as, SIBRA_SERVICE, name_addrs,
                            self.topology.zookeepers)
        self.zk.retry("Joining party", self.zk.party_setup)

    def _find_links(self):
        """
        Create a Link object for each interface, and make a list of all parent
        links.
        """
        for er in self.topology.get_all_edge_routers():
            iface = er.interface
            l = Link(self.addr, self.sendq, self.signing_key, iface)
            self.links[iface.if_id] = l
            if l.parent:
                self.parents.append(l)

    def run(self):
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="SB.worker", daemon=True).start()
        threading.Thread(
            target=thread_safety_net, args=(self.sender,),
            name="SB.sender", daemon=True).start()
        super().run()

    def worker(self):
        # Cycle time should be << SIBRA_TICK, as it determines how often
        # reservations are potentially renewed, and the expiration of old
        # reservation blocks.
        worker_cycle = 1.0
        start = SCIONTime.get_time()
        while True:
            sleep_interval(start, worker_cycle, "SB.worker cycle")
            start = SCIONTime.get_time()
            self.manage_steady_paths()

    def sender(self):
        """
        Handle sending packets on behalf of Link/SteadyPath objects through the
        local socket.
        """
        while True:
            spkt = self.sendq.get()
            dst, port = self._find_dest(spkt)
            if not dst:
                logging.error("Unable to determine first hop for packet:\n%s",
                              spkt)
                continue
            spkt.addrs.src.host = self.addr.host
            logging.debug("Sending packet via %s:%s\n%s", dst, port, spkt)
            self.send(spkt, dst, port)

    def _find_dest(self, spkt):
        dst = spkt.addrs.dst
        if (dst.isd_as == self.addr.isd_as and
                dst.host.TYPE == AddrType.SVC):
            # Destined for a local service
            try:
                spkt.addrs.dst.host = self._svc_lookup(dst)
            except SCIONServiceLookupError:
                return None, None
        return self.get_first_hop(spkt)

    def _svc_lookup(self, addr):
        if addr.host == PT.PATH_MGMT:
            return self.dns_query_topo(PATH_SERVICE)[0]

    def handle_path_reg(self, pkt):
        """
        Handle path registration packets from the local beacon service. First
        determine which interface the segments use, then pass the segment to the
        appropriate Link.
        """
        payload = pkt.get_payload()
        for pcb in payload.pcbs[PST.UP]:
            pcbm = pcb.get_last_pcbm()
            if_id = pcbm.hof.ingress_if
            link = self.links[if_id]
            link.update_segment(pcb)

    def handle_sibra_pkt(self, pkt):
        """
        Handle SIBRA packets. First determine which interface they came from,
        then pass them to the appropriate Link.
        """
        ext = find_ext_hdr(pkt, ExtensionClass.HOP_BY_HOP,
                           SibraExtSteady.EXT_TYPE)
        if not ext:
            logging.error("Packet contains no SIBRA extension header")
            return
        ifid = find_last_ifid(pkt, ext)
        if ifid not in self.links:
            logging.error("Packet came from unknown interface '%s':\n%s",
                          ifid, pkt)
            return
        link = self.links[ifid]
        link.process(pkt, ext)

    def manage_steady_paths(self):
        """
        Create or renew steady paths on all parent links.
        """
        for link in self.parents:
            if link.steadies:
                link.steady_renew()
            else:
                link.steady_add()
