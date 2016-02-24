# Copyright 2014 ETH Zurich
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
:mod:`sciond` --- Reference endhost SCION Daemon
================================================
"""
# Stdlib
import logging
import struct
import threading
from itertools import product

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.crypto.hash_chain import HashChain
from lib.defines import PATH_SERVICE, SCION_UDP_PORT
from lib.errors import SCIONServiceLookupError
from lib.flagtypes import PathSegFlags as PSF
from lib.log import log_exception
from lib.packet.host_addr import haddr_parse
from lib.packet.path import EmptyPath, PathCombinator
from lib.packet.path_mgmt import PathSegmentReq
from lib.packet.pcb_ext import BeaconExtType
from lib.packet.scion_addr import ISD_AS
from lib.path_db import DBResult, PathSegmentDB
from lib.requests import RequestHandler
from lib.sibra.ext.resv import ResvBlockSteady
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.types import (
    AddrType,
    PathMgmtType as PMT,
    PathSegmentType as PST,
    PayloadClass,
)
from lib.util import SCIONTime

SCIOND_API_HOST = "127.255.255.254"
SCIOND_API_PORT = 3333


class SCIONDaemon(SCIONElement):
    """
    The SCION Daemon used for retrieving and combining paths.
    """
    # Max time for a path lookup to succeed/fail.
    TIMEOUT = 5
    # Number of tokens the PS checks when receiving a revocation.
    N_TOKENS_CHECK = 20
    # Time a path segment is cached at a host (in seconds).
    SEGMENT_TTL = 300
    MAX_SEG_NO = 5  # TODO: replace by config variable.

    def __init__(self, conf_dir, addr, api_addr, run_local_api=False,
                 port=SCION_UDP_PORT, is_sim=False):
        """
        Initialize an instance of the class SCIONDaemon.
        """
        super().__init__("sciond", conf_dir, host_addr=addr, port=port,
                         is_sim=is_sim)
        # TODO replace by pathstore instance
        self.up_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL,
                                         max_res_no=self.MAX_SEG_NO)
        self.down_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL,
                                           max_res_no=self.MAX_SEG_NO)
        self.core_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL,
                                           max_res_no=self.MAX_SEG_NO)
        self.requests = RequestHandler.start(
            "SCIONDaemon Requests", self._check_segments, self._fetch_segments,
            self._reply_segments, ttl=self.TIMEOUT, key_map=self._req_key_map,
        )
        self._api_socket = None
        self.daemon_thread = None

        self.PLD_CLASS_MAP = {
            PayloadClass.PATH: {
                PMT.REPLY: self.handle_path_reply,
                PMT.REVOCATION: self.handle_revocation,
            }
        }
        if run_local_api:
            api_addr = api_addr or SCIOND_API_HOST
            self._api_sock = UDPSocket(
                bind=(api_addr, SCIOND_API_PORT, "sciond local API"),
                addr_type=AddrType.IPV4)
            self._socks.add(self._api_sock)

    @classmethod
    def start(cls, conf_dir, addr, api_addr=None, run_local_api=False,
              port=SCION_UDP_PORT, is_sim=False):
        """
        Initializes, starts, and returns a SCIONDaemon object.

        Example of usage:
        sd = SCIONDaemon.start(conf_dir, addr)
        paths = sd.get_paths(isd_as)
        """
        sd = cls(conf_dir, addr, api_addr, run_local_api, port, is_sim)
        sd.daemon_thread = threading.Thread(
            target=thread_safety_net, args=(sd.run,), name="SCIONDaemon.run",
            daemon=True)
        sd.daemon_thread.start()
        return sd

    def stop(self):
        """
        Stop SCIONDaemon thread
        """
        logging.info("Stopping SCIONDaemon")
        super().stop()
        self.daemon_thread.join()

    def handle_request(self, packet, sender, from_local_socket=True):
        # PSz: local_socket may be misleading, especially that we have
        # api_socket which is local (in the localhost sense). What do you think
        # about changing local_socket to as_socket
        """
        Main routine to handle incoming SCION packets.
        """
        if not from_local_socket:  # From localhost (SCIONDaemon API)
            self.api_handle_request(packet, sender)
            return
        super().handle_request(packet, sender, from_local_socket)

    def handle_path_reply(self, pkt):
        """
        Handle path reply from local path server.
        """
        added = set()
        path_reply = pkt.get_payload()
        map_ = {
            PST.UP: self._handle_up_seg,
            PST.DOWN: self._handle_down_seg,
            PST.CORE: self._handle_core_seg,
        }
        for type_, pcbs in path_reply.pcbs.items():
            for pcb in pcbs:
                ret = map_[type_](pcb)
                if not ret:
                    continue
                added.add((ret, pcb.flags))
        logging.debug("Added: %s", added)
        for dst_ia, flags in added:
            self.requests.put(((dst_ia, flags), None))

    def _handle_up_seg(self, pcb):
        first_ia = pcb.get_first_pcbm().isd_as
        last_ia = pcb.get_last_pcbm().isd_as
        if self.addr.isd_as != last_ia:
            return None
        if self.up_segments.update(pcb) == DBResult.ENTRY_ADDED:
            logging.debug("Up segment added: %s", pcb.short_desc())
            return first_ia
        return None

    def _handle_down_seg(self, pcb):
        last_ia = pcb.get_last_pcbm().isd_as
        if self.addr.isd_as == last_ia:
            return None
        if self.down_segments.update(pcb) == DBResult.ENTRY_ADDED:
            logging.debug("Down segment added: %s", pcb.short_desc())
            return last_ia
        return None

    def _handle_core_seg(self, pcb):
        first_ia = pcb.get_first_pcbm().isd_as
        if self.core_segments.update(pcb) == DBResult.ENTRY_ADDED:
            logging.debug("Core segment added: %s", pcb.short_desc())
            return first_ia
        return None

    def api_handle_request(self, packet, sender):
        """
        Handle local API's requests.
        """
        if packet[0] == 0:  # path request
            logging.info('API: path request from %s.', sender)
            threading.Thread(
                target=thread_safety_net,
                args=(self._api_handle_path_request, packet, sender),
                name="SCIONDaemon", daemon=True).start()
        elif packet[0] == 1:  # address request
            self._api_sock.send(self.addr.pack(), sender)
        else:
            logging.warning("API: type %d not supported.", packet[0])

    def _api_handle_path_request(self, packet, sender):
        """
        Path request:
          | \x00 (1B) | ISD (12bits) |  AS (20bits)  |
        Reply:
          |p1_len(1B)|p1((p1_len*8)B)|fh_IP(4B)|fh_port(2B)|mtu(2B)|
           p1_if_count(1B)|p1_if_1(5B)|...|p1_if_n(5B)|
           p2_len(1B)|...
         or b"" when no path found. Only IPv4 supported currently.

        FIXME(kormat): make IP-version independant
        """
        dst_ia = ISD_AS(packet[1:ISD_AS.LEN + 1])
        paths = self.get_paths(dst_ia)
        reply = []
        for path in paths:
            raw_path = path.pack()
            # assumed IPv4 addr
            fwd_if = path.get_fwd_if()
            # Set dummy host addr if path is EmptyPath.
            # TODO(PSz): remove dummy "0.0.0.0" address when API is saner
            haddr = self.ifid2addr.get(fwd_if, haddr_parse("IPV4", "0.0.0.0"))
            path_len = len(raw_path) // 8
            reply.append(struct.pack("!B", path_len) + raw_path +
                         haddr.pack() + struct.pack("!H", SCION_UDP_PORT) +
                         struct.pack("!H", path.mtu) +
                         struct.pack("!B", len(path.interfaces)))
            for interface in path.interfaces:
                isd_as, link = interface
                reply.append(isd_as.pack())
                reply.append(struct.pack("!H", link))
        self._api_sock.send(b"".join(reply), sender)

    def handle_revocation(self, pkt):
        """
        Handle revocation.

        :param rev_info: The RevocationInfo object.
        :type rev_info: :class:`lib.packet.path_mgmt.RevocationInfo`
        """
        rev_info = pkt.get_payload()
        logging.info("Received revocation:\n%s", str(rev_info))
        # Verify revocation.
#         if not HashChain.verify(rev_info.proof, rev_info.rev_token):
#             logging.info("Revocation verification failed.")
#             return
        # Go through all segment databases and remove affected segments.
        deletions = self._remove_revoked_pcbs(self.up_segments,
                                              rev_info.rev_token)
        deletions += self._remove_revoked_pcbs(self.core_segments,
                                               rev_info.rev_token)
        deletions += self._remove_revoked_pcbs(self.down_segments,
                                               rev_info.rev_token)
        logging.info("Removed %d segments due to revocation.", deletions)

    def _remove_revoked_pcbs(self, db, rev_token):
        """
        Removes all segments from 'db' that contain an IF token for which
        rev_token is a preimage (within 20 calls).

        :param db: The PathSegmentDB.
        :type db: :class:`lib.path_db.PathSegmentDB`
        :param rev_token: The revocation token.
        :type rev_token: bytes

        :returns: The number of deletions.
        :rtype: int
        """
        to_remove = []
        for segment in db():
            for iftoken in segment.get_all_iftokens():
                if HashChain.verify(rev_token, iftoken, self.N_TOKENS_CHECK):
                    to_remove.append(segment.get_hops_hash())

        return db.delete_all(to_remove)

    def get_paths(self, dst_ia, requester=None, flags=0):
        """
        Return a list of paths.
        The requester argument holds the address of requester. Used in simulator
        to send path reply.

        :param ISD_AS dst_ia: ISD-AS of the destination.
        :param requester: Path requester address(used in simulator).
        """
        logging.debug("Paths requested for %s", dst_ia)
        if self.addr.isd_as == dst_ia or (
                self.addr.isd_as.any_as() == dst_ia and
                self.topology.is_core_as):
            # Either the destination is the local AS, or the destination is any
            # core AS in this ISD, and the local AS is in the core
            return [EmptyPath()]
        deadline = SCIONTime.get_time() + self.TIMEOUT
        e = threading.Event()
        self.requests.put(((dst_ia, flags), e))
        if not self._wait_for_events([e], deadline):
            logging.error("Query timed out for %s", dst_ia)
            return []
        return self.path_resolution(dst_ia, flags=flags)

    def path_resolution(self, dst_ia, flags=0):
        # dst as == 0 means any core AS in the specified ISD.
        dst_is_core = self._is_core_as(dst_ia) or dst_ia[1] == 0
        sibra = bool(flags & PSF.SIBRA)
        if self.topology.is_core_as:
            if dst_is_core:
                ret = self._resolve_core_core(dst_ia, sibra=sibra)
            else:
                ret = self._resolve_core_not_core(dst_ia, sibra=sibra)
        elif dst_is_core:
            ret = self._resolve_not_core_core(dst_ia, sibra=sibra)
        elif sibra:
            ret = self._resolve_not_core_not_core_sibra(dst_ia)
        else:
            ret = self._resolve_not_core_not_core_scion(dst_ia)
        if not sibra:
            return ret
        # FIXME(kormat): Strip off PCBs, and just return sibra reservation
        # blocks
        return self._sibra_strip_pcbs(self._strip_nones(ret))

    def _resolve_core_core(self, dst_ia, sibra=False):
        """Resolve path from core to core."""
        res = set()
        for cseg in self.core_segments(last_ia=self.addr.isd_as, sibra=sibra,
                                       **dst_ia.params()):
                res.add((None, cseg, None))
        if sibra:
            return res
        return PathCombinator.tuples_to_full_paths(res)

    def _resolve_core_not_core(self, dst_ia, sibra=False):
        """Resolve path from core to non-core."""
        res = set()
        # First check whether there is a direct path.
        for dseg in self.down_segments(
                first_ia=self.addr.isd_as, last_ia=dst_ia, sibra=sibra):
                res.add((None, None, dseg))
        # Check core-down combination.
        for dseg in self.down_segments(last_ia=dst_ia, sibra=sibra):
            dseg_ia = dseg.get_first_pcbm().isd_as
            if self.addr.isd_as == dseg_ia:
                pass
            for cseg in self.core_segments(
                    first_ia=dseg_ia, last_ia=self.addr.isd_as, sibra=sibra):
                res.add((None, cseg, dseg))
        if sibra:
            return res
        return PathCombinator.tuples_to_full_paths(res)

    def _resolve_not_core_core(self, dst_ia, sibra=False):
        """Resolve path from non-core to core."""
        res = set()
        params = dst_ia.params()
        params["sibra"] = sibra
        if dst_ia[0] == self.addr.isd_as[0]:
            # Dst in local ISD. First check whether DST is a (super)-parent.
            for useg in self.up_segments(**params):
                res.add((useg, None, None))
        # Check whether dst is known core AS.
        for cseg in self.core_segments(**params):
            # Check do we have an up-seg that is connected to core_seg.
            cseg_ia = cseg.get_last_pcbm().isd_as
            for useg in self.up_segments(first_ia=cseg_ia, sibra=sibra):
                res.add((useg, cseg, None))
        if sibra:
            return res
        return PathCombinator.tuples_to_full_paths(res)

    def _resolve_not_core_not_core_scion(self, dst_ia):
        """Resolve SCION path from non-core to non-core."""
        up_segs = self.up_segments()
        down_segs = self.down_segments(last_ia=dst_ia)
        core_segs = self._calc_core_segs(dst_ia[0], up_segs, down_segs)
        full_paths = PathCombinator.build_shortcut_paths(up_segs, down_segs)
        for up_seg in up_segs:
            for down_seg in down_segs:
                full_paths.extend(PathCombinator.build_core_paths(
                    up_seg, down_seg, core_segs))
        return full_paths

    def _resolve_not_core_not_core_sibra(self, dst_ia):
        """Resolve SIBRA path from non-core to non-core."""
        res = set()
        up_segs = set(self.up_segments(sibra=True))
        down_segs = set(self.down_segments(last_ia=dst_ia, sibra=True))
        for up_seg, down_seg in product(up_segs, down_segs):
            src_core_ia = up_seg.get_first_pcbm().isd_as
            dst_core_ia = down_seg.get_first_pcbm().isd_as
            if src_core_ia == dst_core_ia:
                res.add((up_seg, down_seg))
                continue
            core_seg = self.core_segments(first_ia=src_core_ia,
                                          last_ia=dst_core_ia, sibra=True)
            if core_seg:
                res.add((up_seg, core_seg, down_seg))
        return res

    def _strip_nones(self, set_):
        """Strip None entries from a set of tuples"""
        res = []
        for tup in set_:
            res.append(tuple(filter(None, tup)))
        return res

    def _sibra_strip_pcbs(self, paths):
        ret = []
        for pcbs in paths:
            resvs = []
            for pcb in pcbs:
                resvs.append(self._sibra_strip_pcb(pcb))
            ret.append(resvs)
        return ret

    def _sibra_strip_pcb(self, pcb):
        last_asm = pcb.ases[-1]
        info = last_asm.find_ext(BeaconExtType.SIBRA_SEG_INFO)
        resv = ResvBlockSteady.from_values(info, pcb.get_n_hops())
        for asm in reversed(pcb.ases):
            resv.sofs.append(asm.find_ext(BeaconExtType.SIBRA_SEG_SOF))
        return resv

    def _wait_for_events(self, events, deadline):
        """
        Wait on a set of events, but only until the specified deadline. Returns
        the number of events that happened while waiting.
        """
        count = 0
        for e in events:
            if e.wait(max(0, deadline - SCIONTime.get_time())):
                count += 1
        return count

    def _check_segments(self, key):
        """
        Called by RequestHandler to check if a given path request can be
        fulfilled.
        """
        dst_ia, flags = key
        return self.path_resolution(dst_ia, flags=flags)

    def _fetch_segments(self, key, _):
        """
        Called by RequestHandler to fetch the requested path.
        """
        dst_ia, flags = key
        try:
            ps = self.dns_query_topo(PATH_SERVICE)[0]
        except SCIONServiceLookupError:
            log_exception("Error querying path service:")
            return
        req = PathSegmentReq.from_values(self.addr.isd_as, dst_ia, flags=flags)
        logging.debug("Sending path request: %s", req.short_desc())
        path_request = self._build_packet(ps, payload=req)
        self.send(path_request, ps)

    def _reply_segments(self, key, e):
        """
        Called by RequestHandler to signal that the request has been fulfilled.
        """
        e.set()

    def _req_key_map(self, key, req_keys):
        """
        Called by RequestHandler to know which requests can be answered by
        `key`.
        """
        ans_ia, ans_flags = key
        ret = []
        for req_ia, req_flags in req_keys:
            if req_flags != ans_flags and (not ans_flags & req_flags):
                # The answer and the request have no flags in common, so skip
                # it.
                continue
            if (req_ia == ans_ia) or (req_ia == ans_ia.any_as()):
                # Covers the case where a request was for ISD-0 (i.e. any path
                # to a core AS in the specified ISD)
                ret.append((req_ia, req_flags))
        return ret

    def _calc_core_segs(self, dst_isd, up_segs, down_segs):
        """
        Calculate all possible core segments joining the provided up and down
        segments. Returns a list of all known segments, and a seperate list of
        the missing AS pairs.
        """
        src_core_ases = set()
        dst_core_ases = set()
        for seg in up_segs:
            src_core_ases.add(seg.get_first_pcbm().isd_as[1])
        for seg in down_segs:
            dst_core_ases.add(seg.get_first_pcbm().isd_as[1])
        # Generate all possible AS pairs
        as_pairs = list(product(src_core_ases, dst_core_ases))
        return self._find_core_segs(self.addr.isd_as[0], dst_isd, as_pairs)

    def _find_core_segs(self, src_isd, dst_isd, as_pairs):
        """
        Given a set of AS pairs across 2 ISDs, return the core segments
        connecting those pairs
        """
        core_segs = []
        for src_core_as, dst_core_as in as_pairs:
            src_ia = ISD_AS.from_values(src_isd, src_core_as)
            dst_ia = ISD_AS.from_values(dst_isd, dst_core_as)
            if src_ia == dst_ia:
                continue
            seg = self.core_segments(first_ia=dst_ia, last_ia=src_ia)
            if seg:
                core_segs.extend(seg)
        return core_segs
