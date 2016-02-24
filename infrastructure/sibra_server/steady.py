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
:mod:`steady` --- steady path management
========================================
"""
# Stdlib
import copy
import logging
import threading

# SCION
from lib.crypto.asymcrypto import sign
from lib.defines import (
    SCION_UDP_PORT,
    SIBRA_MAX_IDX,
    SIBRA_MAX_STEADY_TICKS,
    SIBRA_TICK,
)
from infrastructure.sibra_server.util import seg_to_hops
from lib.errors import SCIONBaseError
from lib.flagtypes import PathSegFlags as PSF
from lib.packet.path import EmptyPath
from lib.packet.path_mgmt import PathRecordsReg
from lib.packet.scion import PacketType as PT
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scion_udp import SCIONUDPHeader
from lib.sibra.ext.info import ResvInfoSteady
from lib.sibra.ext.steady import SibraExtSteady
from lib.sibra.payload import SIBRAPayload
from lib.sibra.pcb_ext.info import SibraSegInfo
from lib.sibra.pcb_ext.sof import SibraSegSOF
from lib.sibra.util import current_tick, tick_to_time
from lib.types import PathSegmentType as PST
from lib.util import SCIONTime, hex_str

RESV_LEN = SIBRA_MAX_STEADY_TICKS - 1
STATE_SETUP = 0
STATE_RUNNING = 1


class SteadyPathErrorNoReservation(SCIONBaseError):
    pass


class SteadyPath(object):
    """
    Class to manage a single steady path
    """
    def __init__(self, addr, sendq, signing_key, seg, bwsnap):
        """
        :param ScionAddr addr: the address of this sibra server
        :param queue.Queue sendq:
            packets written to this queue will be sent by the sibra server
            thread.
        :param bytes signing_key: AS signing key.
        :param PathSegment seg: path segment to use.
        :param BWSnapshot bwsnap: initial bandwidth to request.
        """
        self.addr = addr
        self.sendq = sendq
        self.signing_key = signing_key
        self.seg = seg
        self.bw = bwsnap.to_classes().ceil()
        self.id = SibraExtSteady.mk_path_id(self.addr.isd_as)
        self.idx = 0
        self.blocks = []
        first = self.seg.get_first_pcbm()
        self.remote = first.isd_as
        self._lock = threading.RLock()
        self.state = STATE_SETUP

    def setup(self):
        with self._lock:
            ext = self._create_ext_setup()
            logging.info("Sending setup request:\n%s", ext)
            pkt = self._create_scion_pkt(ext)
            self.sendq.put(pkt)

    def renew(self):
        with self._lock:
            self._renew()

    def _renew(self):
        """
        Renew the steady path, if needed.
        """
        if self.state == STATE_SETUP:
            return
        self._expire_blocks()
        latest = self.blocks[-1]
        if latest.info.exp_tick - current_tick() >= RESV_LEN / 2:
            # If the latest block covers at least half of RESV_LEN, don't bother
            # renewing yet.
            return
        ext = self._create_ext_use()
        ext.renew(self._create_info(inc=True))
        logging.debug("Sending renewal request:\n%s", ext)
        pkt = self._create_sibra_pkt(ext)
        self.sendq.put(pkt)

    def update_seg(self, new_seg):
        with self._lock:
            old_hops = seg_to_hops(self.seg)
            new_hops = seg_to_hops(new_seg)
            if old_hops != new_hops:
                return
            self.seg = new_seg

    def process_reply(self, pkt, ext):
        with self._lock:
            self._process_reply(pkt, ext)

    def _process_reply(self, pkt, ext):
        """
        Process a reply to a setup or renewal request. If the request was
        successful, add the completed request block to the list of active
        blocks. If the request was denied, retry with the suggested bandwidth.
        """
        if ext.accepted:
            self.blocks.append(ext.req_block)
            if ext.setup:
                logging.info("Setup successful: %s", ext.req_block.info)
                self.state = STATE_RUNNING
            else:
                logging.debug("Renewal successful: %s", ext.req_block.info)
            self._register_path()
            return
        req_bw = ext.req_block.info.bw
        self.bw = ext.get_min_offer()
        if ext.setup:
            logging.info("Setup request for %s denied", req_bw)
            self._setup()
        else:
            logging.info("Renewal request for %s denied", req_bw)
            self._renew()

    def _expire_blocks(self):
        """
        Check the current reservation blocks and remove any that have expired.
        """
        now = SCIONTime.get_time()
        while True:
            if not self.blocks:
                raise SteadyPathErrorNoReservation
            act_block = self.blocks[0]
            exp = act_block.info.exp_ts()
            if now > exp:
                logging.debug("Reservation expired, removed: %s",
                              act_block.info)
                self.blocks.pop(0)
            elif len(self.blocks) > 1 and (now + SIBRA_TICK) > exp:
                # Don't use a block that expires this interval, if possible
                logging.debug("Reservation expiring soon, removed: %s",
                              act_block.info)
                self.blocks.pop(0)
            else:
                break

    def _create_ext_setup(self):
        """
        Create a SIBRA extension for path setup
        """
        info = self._create_info()
        return SibraExtSteady.setup_from_values(
            info, self.seg.get_n_hops(), self.id)

    def _create_ext_use(self):
        """
        Create a SIBRA extension for path use
        """
        return SibraExtSteady.use_from_values(self.id, self.blocks[0])

    def _create_info(self, inc=False):
        """
        Create a reservation info block, optionally incrementing the reservation
        index
        """
        if inc:
            self._inc_idx()
        exp_tick = current_tick() + RESV_LEN
        return ResvInfoSteady.from_values(
            tick_to_time(exp_tick), bw_cls=self.bw, index=self.idx)

    def _inc_idx(self):
        """
        Increment the last used reservation index
        """
        self.idx = (self.idx + 1) % SIBRA_MAX_IDX

    def _create_hdrs(self):
        """
        Create headers for a SCION packet
        """
        dest = SCIONAddr.from_values(self.remote, PT.SB_PKT)
        cmn_hdr, addr_hdr = build_base_hdrs(self.addr, dest)
        payload = SIBRAPayload()
        udp_hdr = SCIONUDPHeader.from_values(
            self.addr, SCION_UDP_PORT, dest, SCION_UDP_PORT, payload)
        return cmn_hdr, addr_hdr, udp_hdr, payload

    def _create_scion_pkt(self, ext):
        """
        Create a packet that uses a SCION path
        """
        cmn_hdr, addr_hdr, udp_hdr, payload = self._create_hdrs()
        return SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, self.seg.get_path(True), [ext], udp_hdr, payload)

    def _create_sibra_pkt(self, ext):
        """
        Create a packet that uses a SIBRA path
        """
        ext.setup = False
        ext.active_blocks = self.blocks[:1]
        cmn_hdr, addr_hdr, udp_hdr, payload = self._create_hdrs()
        return SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, EmptyPath(), [ext], udp_hdr, payload)

    def _register_path(self):
        pcb = self._create_reg_pcb()
        pkt = self._create_reg_pkt(pcb)
        logging.debug("Registering path with local path server")
        self.sendq.put(pkt)
        pkt = self._create_reg_pkt(pcb, core=True)
        logging.debug("Registering path with core path server in %s",
                      self.remote)
        self.sendq.put(pkt)

    def _create_reg_pcb(self):
        pcb = copy.deepcopy(self.seg)
        # TODO(kormat): It might make sense to remove peer markings also, but
        # they might also be needed for sibra steady paths that traverse peer
        # links in the future.
        pcb.remove_signatures()
        latest = self.blocks[-1]
        for asm, sof in zip(reversed(pcb.ases), latest.sofs):
            asm.add_ext(SibraSegSOF.from_values(sof))
        last_asm = pcb.ases[-1]
        last_asm.add_ext(SibraSegInfo.from_values(self.id, latest.info))
        last_asm.sig = sign(pcb.pack(), self.signing_key)
        pcb.flags |= PSF.SIBRA
        return pcb

    def _create_reg_pkt(self, pcb, core=False):
        if core:
            dst_ia = self.remote
            path = self.seg.get_path(True)
            type_ = PST.DOWN
        else:
            dst_ia = self.addr.isd_as
            path = EmptyPath()
            type_ = PST.UP
        pld = PathRecordsReg.from_values({type_: [pcb]})
        dest = SCIONAddr.from_values(dst_ia, PT.PATH_MGMT)
        cmn_hdr, addr_hdr = build_base_hdrs(self.addr, dest)
        udp_hdr = SCIONUDPHeader.from_values(
            self.addr, SCION_UDP_PORT, dest, SCION_UDP_PORT, pld)
        return SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, path, [], udp_hdr, pld)

    def __str__(self):
        with self._lock:
            if self.blocks:
                act_info = self.blocks[0].info
            else:
                act_info = "(No active blocks)"
            return "SteadyPath %s to %s: %s" % (
                hex_str(self.id), self.remote, act_info)
