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
import logging
import threading
import time
from queue import Queue

# SCION
from lib.crypto.asymcrypto import get_sig_key
from lib.defines import SIBRA_SERVICE
from lib.packet.ext_util import find_ext_hdr
from lib.packet.path_mgmt.seg_recs import PathRecordsReg
from lib.path_db import DBResult, PathSegmentDB
from lib.sibra.ext.steady import SibraExtSteady
from lib.sibra.state.state import SibraState
from lib.sibra.util import BWSnapshot
from lib.thread import thread_safety_net
from lib.types import (
    ExtensionClass,
    PathMgmtType as PMT,
    PathSegmentType as PST,
    PayloadClass,
)
from lib.util import (
    SCIONTime,
    hex_str,
    sleep_interval,
)
from lib.zk.id import ZkID
from lib.zk.zk import Zookeeper
from scion_elem.scion_elem import SCIONElement
from sibra_server.steady import (
    SteadyPath,
    SteadyPathErrorNoReservation,
)
from sibra_server.util import find_last_ifid


# How long to wait for path propagation before setting up steady paths over
# core links
STARTUP_WAIT = 30


class SibraServerBase(SCIONElement):
    """
    Base class for the SIBRA service, which is responsible for managing steady
    paths on all interfaces in the local AS.
    """
    SERVICE_TYPE = SIBRA_SERVICE
    PST_TYPE = None

    def __init__(self, server_id, conf_dir, prom_export=None):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param str prom_export: prometheus export address.
        """
        super().__init__(server_id, conf_dir, prom_export=prom_export)
        self.sendq = Queue()
        self.signing_key = get_sig_key(self.conf_dir)
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
            PayloadClass.PATH: {PMT.REG: self.handle_path_reg},
            PayloadClass.SIBRA: {PayloadClass.SIBRA: self.handle_sibra_pkt},
        }
        self._find_links()
        zkid = ZkID.from_values(self.addr.isd_as, self.id,
                                [(self.addr.host, self._port)]).pack()
        self.zk = Zookeeper(self.addr.isd_as, SIBRA_SERVICE, zkid,
                            self.topology.zookeepers)
        self.zk.retry("Joining party", self.zk.party_setup)

    def _find_links(self):
        for br in self.topology.border_routers:
            for ifid, intf in br.interfaces.items():
                self.link_states[ifid] = SibraState(
                    intf.bandwidth, self.addr.isd_as)
                self.link_types[ifid] = intf.link_type

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
            dst, port = self.get_first_hop(spkt)
            if not dst:
                logging.error("Unable to determine first hop for packet:\n%s",
                              spkt)
                continue
            spkt.addrs.src.host = self.addr.host
            logging.debug("Dst: %s Port: %s\n%s", dst, port, spkt)
            self.send(spkt, dst, port)

    def handle_path_reg(self, cpld, meta):
        """
        Handle path registration packets from the local beacon service. First
        determine which interface the segments use, then pass the segment to the
        appropriate Link.
        """
        pmgt = cpld.contents
        payload = pmgt.contents
        assert isinstance(payload, PathRecordsReg), type(payload)
        meta.close()
        name = PST.to_str(self.PST_TYPE)
        with self.lock:
            for type_, pcb in payload.iter_pcbs():
                if type_ == self.PST_TYPE:
                    self._add_segment(pcb, name)

    def _add_segment(self, pcb, name):
        res = self.segments.update(pcb)
        if res == DBResult.ENTRY_ADDED:
            logging.info("%s Segment added: %s", name, pcb.short_desc())
        elif res == DBResult.ENTRY_UPDATED:
            logging.debug("%s Segment updated: %s", name, pcb.short_desc())
        isd_as = pcb.first_ia()
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
            # This shouldn't happen - if the local BR accepted the reservation,
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
        ifid = seg.last_hof().ingress_if
        link_state = self.link_states[ifid]
        link_type = self.link_types[ifid]
        # FIXME(kormat): un-hardcode these bandwidths
        bwsnap = BWSnapshot(500 * 1024, 500 * 1024)
        steady = SteadyPath(self.addr, self._port, self.sendq, self.signing_key,
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
