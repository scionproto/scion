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
import time
from queue import Queue

# SCION
from infrastructure.scion_elem import SCIONElement
from infrastructure.sibra_server.steady import (
    SteadyPath,
    SteadyPathErrorNoReservation,
)
from infrastructure.sibra_server.util import find_last_ifid
from lib.defines import (
    PATH_SERVICE,
    SCION_UDP_PORT,
    SIBRA_SERVICE,
)
from lib.errors import SCIONServiceLookupError
from lib.packet.ext_util import find_ext_hdr
from lib.packet.scion import SVCType
from lib.path_db import DBResult, PathSegmentDB
from lib.sibra.ext.steady import SibraExtSteady
from lib.sibra.state.state import SibraState
from lib.sibra.util import BWSnapshot
from lib.thread import thread_safety_net
from lib.types import (
    AddrType,
    ExtensionClass,
    PathMgmtType as PMT,
    PathSegmentType as PST,
    PayloadClass,
    SIBRAPayloadType,
)
from lib.util import (
    SCIONTime,
    get_sig_key_file_path,
    hex_str,
    read_file,
    sleep_interval,
)
from lib.zookeeper import Zookeeper

# How long to wait for path propagation before setting up steady paths over
# routing links
STARTUP_WAIT = 30


class SibraServerBase(SCIONElement):
    """
    Base class for the SIBRA service, which is responsible for managing steady
    paths on all interfaces in the local AS.
    """
    SERVICE_TYPE = SIBRA_SERVICE
    PST_TYPE = None

    def __init__(self, server_id, conf_dir):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        """
        super().__init__(server_id, conf_dir)
        self.sendq = Queue()
        sig_key_file = get_sig_key_file_path(self.conf_dir)
        self.signing_key = base64.b64decode(read_file(sig_key_file))
        self.segments = PathSegmentDB(max_res_no=1)
        # Maps of {ISD-AS: {steady path id: steady path}} for all incoming
        # (srcs) and outgoing (dests) steady paths:
        self.srcs = {}
        self.dests = {}
        # Map of SibraState objects by interface ID
        self.link_states = {}
        # Map of link types by interface ID
        self.link_types = {}
        self.lock = threading.Lock()
        self.CTRL_PLD_CLASS_MAP = {
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
        for er in self.topology.get_all_edge_routers():
            iface = er.interface
            self.link_states[iface.if_id] = SibraState(
                iface.bandwidth, self.addr.isd_as)
            self.link_types[iface.if_id] = iface.link_type

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
        while self.run_flag.is_set():
            sleep_interval(start, worker_cycle, "SB.worker cycle")
            start = SCIONTime.get_time()
            with self.lock:
                self.manage_steady_paths()

    def sender(self):
        """
        Handle sending packets on behalf of Link/SteadyPath objects through the
        local socket.
        """
        while self.run_flag.is_set():
            spkt = self.sendq.get()
            dst, port = self._find_dest(spkt)
            if not dst:
                logging.error("Unable to determine first hop for packet:\n%s",
                              spkt)
                continue
            spkt.addrs.src.host = self.addr.host
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
        if addr.host == SVCType.PS:
            return self.dns_query_topo(PATH_SERVICE)[0]

    def handle_path_reg(self, pkt):
        """
        Handle path registration packets from the local beacon service. First
        determine which interface the segments use, then pass the segment to the
        appropriate Link.
        """
        payload = pkt.get_payload()
        name = PST.to_str(self.PST_TYPE)
        with self.lock:
            for pcb in payload.pcbs[self.PST_TYPE]:
                self._add_segment(pcb, name)

    def _add_segment(self, pcb, name):
        res = self.segments.update(pcb)
        if res == DBResult.ENTRY_ADDED:
            logging.info("%s Segment added: %s", name, pcb.short_desc())
        elif res == DBResult.ENTRY_UPDATED:
            logging.debug("%s Segment updated: %s", name, pcb.short_desc())
        isd_as = pcb.get_first_pcbm().isd_as
        if isd_as not in self.dests:
            logging.debug("Found new destination ISD-AS: %s", isd_as)
            self.dests[isd_as] = {}
        for steady in self.dests[isd_as].values():
            steady.update_seg(pcb)

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
        if not ext.steady:
            logging.error("Received non-steady SIBRA packet:\n%s", pkt)
            return
        if not ext.req_block:
            logging.error("Received non-request SIBRA packet:\n%s", pkt)
            return
        with self.lock:
            if ext.fwd:
                self._process_req(pkt, ext)
            else:
                self._process_reply(pkt, ext)

    def _process_req(self, pkt, ext):
        """Process a steady path request."""
        path_id = ext.path_ids[0]
        self.srcs.setdefault(ext.src_ia, {})
        if ext.setup and path_id in self.srcs[ext.src_ia]:
            logging.error("Setup request for existing path id: %s\n%s",
                          hex_str(path_id), pkt)
            return
        elif not ext.setup and path_id not in self.srcs[ext.src_ia]:
            logging.error("Renewal request for non-existant path id: %s\n%s",
                          hex_str(path_id), pkt)
            return
        ifid = find_last_ifid(pkt, ext)
        if ifid not in self.link_states:
            logging.error("Packet came from unknown interface '%s':\n%s",
                          ifid, pkt)
            return
        if not ext.accepted:
            # Request was already rejected, so just send the packet back.
            pkt.reverse()
            self.sendq.put(pkt)
            return
        state = self.link_states[ifid]
        req_info = ext.req_block.info
        bwsnap = req_info.bw.to_snap()
        bwhint = state.add_steady(path_id, req_info.index, bwsnap,
                                  req_info.exp_tick, True, ext.setup)
        if bwhint is not None:
            # This shouldn't happen - if the local ER accepted the reservation,
            # then there should be enough bandwidth available for it. This means
            # our state is out of sync.
            logging.critical("Requested: %s Available bandwidth: %s\n%s",
                             bwsnap, bwhint, pkt)
            return
        self.srcs[ext.src_ia][path_id] = None
        # All is good, return the packet to the requestor.
        pkt.reverse()
        self.sendq.put(pkt)

    def _process_reply(self, pkt, ext):
        """Process a reply to a steady path request."""
        path_id = ext.path_ids[0]
        dest = pkt.addrs.src.isd_as
        steady = self.dests[dest].get(path_id, None)
        if not steady:
            logging.error("Unknown path ID: %s:\n%s",
                          hex_str(path_id), pkt)
            return
        steady.process_reply(pkt, ext)

    def manage_steady_paths(self):
        """Create or renew steady paths to all destinations."""
        now = time.time()
        for isd_as, steadies in self.dests.items():
            if not steadies and (now - self._startup >= STARTUP_WAIT):
                self._steady_add(isd_as)
                continue
            for id_, steady in list(steadies.items()):
                try:
                    steady.renew()
                except SteadyPathErrorNoReservation:
                    del steadies[id_]

    def _steady_add(self, isd_as):
        seg = self._pick_seg(isd_as)
        if not seg:
            del self.dests[isd_as]
            return
        ifid = seg.get_last_pcbm().hof.ingress_if
        link_state = self.link_states[ifid]
        link_type = self.link_types[ifid]
        # FIXME(kormat): un-hardcode these bandwidths
        bwsnap = BWSnapshot(500 * 1024, 500 * 1024)
        steady = SteadyPath(self.addr, self.sendq, self.signing_key,
                            link_type, link_state, seg, bwsnap)
        self.dests[isd_as][steady.id] = steady
        logging.debug("Setting up steady path %s -> %s over %s",
                      self.addr.isd_as, isd_as, seg.short_desc())
        steady.setup()

    def _pick_seg(self, isd_as):
        """Select the segment to use for a steady path."""
        # FIXME(kormat): this needs actual logic
        # For now, we use the shortest path
        segs = self.segments(first_ia=isd_as)
        if segs:
            return segs[0]
        if not self._quiet_startup():
            logging.warning("No segments to %s", isd_as)
