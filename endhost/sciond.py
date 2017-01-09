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
import os
import struct
import threading
from itertools import product

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.crypto.hash_tree import ConnectedHashTree
from lib.defines import (
    PATH_FLAG_SIBRA,
    PATH_SERVICE,
    SCION_UDP_EH_DATA_PORT,
)
from lib.errors import SCIONServiceLookupError
from lib.log import log_exception
from lib.msg_meta import SockOnlyMetadata
from lib.packet.host_addr import HostAddrNone
from lib.packet.path import PathCombinator, SCIONPath
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.path_mgmt.seg_req import PathSegmentReq
from lib.packet.scion_addr import ISD_AS
from lib.packet.scmp.types import SCMPClass, SCMPPathClass
from lib.path_db import DBResult, PathSegmentDB
from lib.requests import RequestHandler
from lib.sibra.ext.resv import ResvBlockSteady
from lib.socket import ReliableSocket
from lib.thread import thread_safety_net
from lib.types import (
    PathMgmtType as PMT,
    PathSegmentType as PST,
    PayloadClass,
)
from lib.util import SCIONTime
SCIOND_API_SOCKDIR = "/run/shm/sciond/"


class SCIONDaemon(SCIONElement):
    """
    The SCION Daemon used for retrieving and combining paths.
    """
    # Max time for a path lookup to succeed/fail.
    TIMEOUT = 5
    # Time a path segment is cached at a host (in seconds).
    SEGMENT_TTL = 300
    MAX_SEG_NO = 5  # TODO: replace by config variable.

    def __init__(self, conf_dir, addr, api_addr, run_local_api=False,
                 port=None):
        """
        Initialize an instance of the class SCIONDaemon.
        """
        super().__init__("sciond", conf_dir, host_addr=addr, port=port)
        # TODO replace by pathstore instance
        self.up_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL,
                                         max_res_no=self.MAX_SEG_NO)
        self.down_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL,
                                           max_res_no=self.MAX_SEG_NO)
        self.core_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL,
                                           max_res_no=self.MAX_SEG_NO)
        req_name = "SCIONDaemon Requests %s" % self.addr.isd_as
        self.requests = RequestHandler.start(
            req_name, self._check_segments, self._fetch_segments,
            self._reply_segments, ttl=self.TIMEOUT, key_map=self._req_key_map,
        )
        self._api_sock = None
        self.daemon_thread = None
        os.makedirs(SCIOND_API_SOCKDIR, exist_ok=True)
        self.api_addr = (api_addr or
                         os.path.join(SCIOND_API_SOCKDIR,
                                      "%s.sock" % self.addr.isd_as))

        self.CTRL_PLD_CLASS_MAP = {
            PayloadClass.PATH: {
                PMT.REPLY: self.handle_path_reply,
                PMT.REVOCATION: self.handle_revocation,
            }
        }

        self.SCMP_PLD_CLASS_MAP = {
            SCMPClass.PATH:
                {SCMPPathClass.REVOKED_IF: self.handle_scmp_revocation},
        }

        if run_local_api:
            self._api_sock = ReliableSocket(bind=(self.api_addr, "sciond"))
            self._socks.add(self._api_sock, self.handle_accept)

    @classmethod
    def start(cls, conf_dir, addr, api_addr=None, run_local_api=False, port=0):
        """
        Initializes, starts, and returns a SCIONDaemon object.

        Example of usage:
        sd = SCIONDaemon.start(conf_dir, addr)
        paths = sd.get_paths(isd_as)
        """
        inst = cls(conf_dir, addr, api_addr, run_local_api, port)
        name = "SCIONDaemon.run %s" % inst.addr.isd_as
        inst.daemon_thread = threading.Thread(
            target=thread_safety_net, args=(inst.run,), name=name, daemon=True)
        inst.daemon_thread.start()
        logging.debug("sciond started with api_addr = %s", inst.api_addr)
        return inst

    def _get_msg_meta(self, packet, addr, sock):
        if sock != self._udp_sock:
            return packet, SockOnlyMetadata.from_values(sock)  # API socket
        else:
            return super()._get_msg_meta(packet, addr, sock)

    def handle_msg_meta(self, msg, meta):
        """
        Main routine to handle incoming SCION messages.
        """
        if isinstance(meta, SockOnlyMetadata):  # From SCIOND API
            self.api_handle_request(msg, meta)
            return
        logging.debug("handle_msg_meta()")
        super().handle_msg_meta(msg, meta)

    def handle_path_reply(self, path_reply, meta):
        """
        Handle path reply from local path server.
        """
        added = set()
        map_ = {
            PST.UP: self._handle_up_seg,
            PST.DOWN: self._handle_down_seg,
            PST.CORE: self._handle_core_seg,
        }
        for type_, pcb in path_reply.iter_pcbs():
            ret = map_[type_](pcb)
            if not ret:
                continue
            flags = (PATH_FLAG_SIBRA,) if pcb.is_sibra() else ()
            added.add((ret, flags))
        logging.debug("Added: %s", added)
        for dst_ia, flags in added:
            self.requests.put(((dst_ia, flags), None))
        logging.debug("Closing meta")
        meta.close()

    def _handle_up_seg(self, pcb):
        if self.addr.isd_as != pcb.last_ia():
            return None
        if self.up_segments.update(pcb) == DBResult.ENTRY_ADDED:
            logging.debug("Up segment added: %s", pcb.short_desc())
            return pcb.first_ia()
        return None

    def _handle_down_seg(self, pcb):
        last_ia = pcb.last_ia()
        if self.addr.isd_as == last_ia:
            return None
        if self.down_segments.update(pcb) == DBResult.ENTRY_ADDED:
            logging.debug("Down segment added: %s", pcb.short_desc())
            return last_ia
        return None

    def _handle_core_seg(self, pcb):
        if self.core_segments.update(pcb) == DBResult.ENTRY_ADDED:
            logging.debug("Core segment added: %s", pcb.short_desc())
            return pcb.first_ia()
        return None

    def api_handle_request(self, msg, meta):
        """
        Handle local API's requests.
        """
        if msg[0] == 0:  # path request
            logging.debug('API: path request')
            threading.Thread(
                target=thread_safety_net,
                args=(self._api_handle_path_request, msg, meta),
                daemon=True).start()
        elif msg[0] == 1:  # address request
            logging.debug('API: local ISD-AS request')
            self.send_meta(self.addr.isd_as.pack(), meta)
        else:
            logging.warning("API: type %d not supported.", msg[0])

    def _api_handle_path_request(self, msg, meta):
        """
        Path request:
          | \x00 (1B) | ISD (12bits) |  AS (20bits)  |
        Reply:
          |p1_len(1B)|p1((p1_len*8)B)|fh_type(1B)|fh_IP(?B)|fh_port(2B)|mtu(2B)|
           p1_if_count(1B)|p1_if_1(5B)|...|p1_if_n(5B)|
           p2_len(1B)|...
         or b"" when no path found.
        """
        dst_ia = ISD_AS(msg[1:ISD_AS.LEN + 1])
        thread = threading.current_thread()
        thread.name = "SCIONDaemon API id:%s %s -> %s" % (
            thread.ident, self.addr.isd_as, dst_ia)
        paths = self.get_paths(dst_ia)
        reply = []
        logging.debug("Replying to api request for %s with %d paths",
                      dst_ia, len(paths))
        for path in paths:
            raw_path = path.pack()
            fwd_if = path.get_fwd_if()
            # Set dummy host addr if path is empty.
            if fwd_if == 0:
                haddr, port = HostAddrNone(), SCION_UDP_EH_DATA_PORT
            else:
                br = self.ifid2br[fwd_if]
                haddr, port = br.addr, br.port
            path_len = len(raw_path) // 8
            reply.append(struct.pack("!B", path_len) + raw_path +
                         struct.pack("!B", haddr.TYPE) + haddr.pack() +
                         struct.pack("!H", port) +
                         struct.pack("!H", path.mtu) +
                         struct.pack("!B", len(path.interfaces)))
            for interface in path.interfaces:
                isd_as, link = interface
                reply.append(isd_as.pack())
                reply.append(struct.pack("!H", link))
        self.send_meta(b"".join(reply), meta)

    def handle_scmp_revocation(self, pld, meta):
        rev_info = RevocationInfo.from_raw(pld.info.rev_info)
        self.handle_revocation(rev_info, meta)

    def handle_revocation(self, rev_info, meta):
        assert isinstance(rev_info, RevocationInfo)
        if not self._validate_revocation(rev_info):
            return
        # Go through all segment databases and remove affected segments.
        removed_up = self._remove_revoked_pcbs(self.up_segments, rev_info)
        removed_core = self._remove_revoked_pcbs(self.core_segments, rev_info)
        removed_down = self._remove_revoked_pcbs(self.down_segments, rev_info)
        logging.info("Removed %d UP- %d CORE- and %d DOWN-Segments." %
                     (removed_up, removed_core, removed_down))

    def _remove_revoked_pcbs(self, db, rev_info):
        """
        Removes all segments from 'db' that contain an IF token for which
        rev_token is a preimage (within 20 calls).

        :param db: The PathSegmentDB.
        :type db: :class:`lib.path_db.PathSegmentDB`
        :param rev_info: The revocation info
        :type rev_info: RevocationInfo

        :returns: The number of deletions.
        :rtype: int
        """

        if not ConnectedHashTree.verify_epoch(rev_info.p.epoch):
            logging.debug(
                "Failed to verify epoch: rev_info epoch %d,current epoch %d."
                % (rev_info.p.epoch, ConnectedHashTree.get_current_epoch()))
            return 0

        to_remove = []
        for segment in db(full=True):
            for asm in segment.iter_asms():
                if self._verify_revocation_for_asm(rev_info, asm):
                    logging.debug("Removing segment: %s" % segment.short_desc())
                    to_remove.append(segment.get_hops_hash())
        return db.delete_all(to_remove)

    def get_paths(self, dst_ia, flags=()):
        """Return a list of paths."""
        logging.debug("Paths requested for %s %s", dst_ia, flags)
        if self.addr.isd_as == dst_ia or (
                self.addr.isd_as.any_as() == dst_ia and
                self.topology.is_core_as):
            # Either the destination is the local AS, or the destination is any
            # core AS in this ISD, and the local AS is in the core
            empty = SCIONPath()
            empty.mtu = self.topology.mtu
            return [empty]
        deadline = SCIONTime.get_time() + self.TIMEOUT
        e = threading.Event()
        self.requests.put(((dst_ia, flags), e))
        if not self._wait_for_events([e], deadline):
            logging.error("Query timed out for %s", dst_ia)
            return []
        return self.path_resolution(dst_ia, flags=flags)

    def path_resolution(self, dst_ia, flags=()):
        # dst as == 0 means any core AS in the specified ISD.
        dst_is_core = self.is_core_as(dst_ia) or dst_ia[1] == 0
        sibra = PATH_FLAG_SIBRA in flags
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
            dseg_ia = dseg.first_ia()
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
            for useg in self.up_segments(first_ia=cseg.last_ia(), sibra=sibra):
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
        tuples = []
        for up_seg in up_segs:
            for down_seg in down_segs:
                tuples.append((up_seg, None, down_seg))
                for core_seg in core_segs:
                    tuples.append((up_seg, core_seg, down_seg))
        full_paths.extend(PathCombinator.tuples_to_full_paths(tuples))
        return full_paths

    def _resolve_not_core_not_core_sibra(self, dst_ia):
        """Resolve SIBRA path from non-core to non-core."""
        res = set()
        up_segs = set(self.up_segments(sibra=True))
        down_segs = set(self.down_segments(last_ia=dst_ia, sibra=True))
        for up_seg, down_seg in product(up_segs, down_segs):
            src_core_ia = up_seg.first_ia()
            dst_core_ia = down_seg.first_ia()
            if src_core_ia == dst_core_ia:
                res.add((up_seg, down_seg))
                continue
            for core_seg in self.core_segments(first_ia=dst_core_ia,
                                               last_ia=src_core_ia, sibra=True):
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
        assert pcb.is_sibra()
        pcb_ext = pcb.sibra_ext
        resv_info = pcb_ext.info
        resv = ResvBlockSteady.from_values(resv_info, pcb.get_n_hops())
        asms = pcb.iter_asms()
        if pcb_ext.p.up:
            asms = reversed(list(asms))
        iflist = []
        for sof, asm in zip(pcb_ext.iter_sofs(), asms):
            resv.sofs.append(sof)
            iflist.extend(self._sibra_add_ifs(
                asm.isd_as(), sof, resv_info.fwd_dir))
        assert resv.num_hops == len(resv.sofs)
        return pcb_ext.p.id, resv, iflist

    def _sibra_add_ifs(self, isd_as, sof, fwd):
        def _add(ifid):
            if ifid:
                ret.append((isd_as, ifid))
        ret = []
        if fwd:
            _add(sof.ingress)
            _add(sof.egress)
        else:
            _add(sof.egress)
            _add(sof.ingress)
        return ret

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
            addr, port = self.dns_query_topo(PATH_SERVICE)[0]
        except SCIONServiceLookupError:
            log_exception("Error querying path service:")
            return
        req = PathSegmentReq.from_values(self.addr.isd_as, dst_ia, flags=flags)
        logging.debug("Sending path request: %s", req.short_desc())
        meta = self.DefaultMeta.from_values(host=addr, port=port)
        self.send_meta(req, meta)

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
        ans_f_set = set(ans_flags)
        ret = []
        for req_ia, req_flags in req_keys:
            req_f_set = set(req_flags)
            if req_f_set != ans_f_set and (not ans_f_set & req_f_set):
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
            src_core_ases.add(seg.first_ia()[1])
        for seg in down_segs:
            dst_core_ases.add(seg.first_ia()[1])
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
