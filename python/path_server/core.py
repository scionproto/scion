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
:mod:`core` --- Core path server
================================
"""
# Stdlib
import logging
from collections import deque

# SCION
from lib.defines import PATH_FLAG_CACHEONLY, PATH_FLAG_SIBRA
from lib.packet.path_mgmt.seg_recs import PathRecordsReply
from lib.packet.path_mgmt.seg_req import PathSegmentReq
from lib.packet.svc import SVCType
from lib.types import PathMgmtType as PMT, PathSegmentType as PST
from lib.zk.errors import ZkNoConnection
from path_server.base import PathServer


class CorePathServer(PathServer):
    """
    SCION Path Server in a core AS. Stores intra ISD down-segments as well as
    core segments and forwards inter-ISD path requests to the corresponding path
    server.
    """
    def __init__(self, server_id, conf_dir):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        """
        super().__init__(server_id, conf_dir)
        # Sanity check that we should indeed be a core path server.
        assert self.topology.is_core_as, "This shouldn't be a local PS!"
        self._master_id = None  # Address of master core Path Server.
        self._segs_to_master = deque()
        self._segs_to_prop = deque()

    def _update_master(self):
        """
        Read master's address from shared lock, and if new master is elected
        sync it with segments.
        """
        if self.zk.have_lock():
            self._segs_to_master.clear()
            self._master_id = None
            return
        try:
            curr_master = self.zk.get_lock_holder()
        except ZkNoConnection:
            logging.warning("_update_master(): ZkNoConnection.")
            return
        if curr_master and curr_master == self._master_id:
            return
        self._master_id = curr_master
        if not curr_master:
            logging.warning("_update_master(): current master is None.")
            return
        logging.debug("New master is: %s", self._master_id)
        self._sync_master()

    def _sync_master(self):
        """
        Feed newly-elected master with segments.
        """
        assert not self.zk.have_lock()
        assert self._master_id
        # TODO(PSz): consider mechanism for avoiding a registration storm.
        core_segs = []
        # Find all core segments from remote ISDs
        for pcb in self.core_segments(full=True):
            if pcb.first_ia()[0] != self.addr.isd_as[0]:
                core_segs.append(pcb)
        # Find down-segments from local ISD.
        down_segs = self.down_segments(full=True, last_isd=self.addr.isd_as[0])
        logging.debug("Syncing with master: %s", self._master_id)
        seen_ases = set()
        for seg_type, segs in [(PST.CORE, core_segs), (PST.DOWN, down_segs)]:
            for pcb in segs:
                key = pcb.first_ia(), pcb.last_ia()
                # Send only one SCION segment for given (src, dst) pair.
                if not pcb.is_sibra() and key in seen_ases:
                    continue
                seen_ases.add(key)
                self._segs_to_master.append((seg_type, pcb))

    def _handle_up_segment_record(self, pcb, **kwargs):
        logging.error("Core Path Server received up-segment record!")
        return set()

    def _handle_down_segment_record(self, pcb, from_master=False,
                                    from_zk=False):
        added = self._add_segment(pcb, self.down_segments, "Down")
        first_ia = pcb.first_ia()
        last_ia = pcb.last_ia()
        if first_ia == self.addr.isd_as:
            # Segment is to us, so propagate to all other core ASes within the
            # local ISD.
            self._segs_to_prop.append((PST.DOWN, pcb))
        if (first_ia[0] == last_ia[0] == self.addr.isd_as[0] and not from_zk):
            # Sync all local down segs via zk
            self._segs_to_zk.append((PST.DOWN, pcb))
        if added:
            return set([(last_ia, pcb.is_sibra())])
        return set()

    def _handle_core_segment_record(self, pcb, from_master=False,
                                    from_zk=False):
        """Handle registration of a core segment."""
        first_ia = pcb.first_ia()
        reverse = False
        if pcb.is_sibra() and first_ia == self.addr.isd_as:
            reverse = True
        added = self._add_segment(pcb, self.core_segments, "Core",
                                  reverse=reverse)
        if not from_zk and not from_master:
            if first_ia[0] == self.addr.isd_as[0]:
                # Local core segment, share via ZK
                self._segs_to_zk.append((PST.CORE, pcb))
            else:
                # Remote core segment, send to master
                self._segs_to_master.append((PST.CORE, pcb))
        if not added:
            return set()
        # Send pending requests that couldn't be processed due to the lack of
        # a core segment to the destination PS. Don't use SIBRA PCBs for that.
        if not pcb.is_sibra():
            self._handle_waiting_targets(pcb)
        ret = set([(first_ia, pcb.is_sibra())])
        if first_ia[0] != self.addr.isd_as[0]:
            # Remote core segment, signal the entire ISD
            ret.add((first_ia.any_as(), pcb.is_sibra()))
        return ret

    def _dispatch_params(self, pld, meta):
        params = {}
        if (meta.ia == self.addr.isd_as and pld.PAYLOAD_TYPE == PMT.REPLY):
            params["from_master"] = True
        return params

    def _propagate_and_sync(self):
        super()._propagate_and_sync()
        if self.zk.have_lock():
            self._prop_to_core()
        else:
            self._prop_to_master()

    def _prop_to_core(self):
        assert self.zk.have_lock()
        if not self._segs_to_prop:
            return
        logging.debug("Propagating %d segment(s) to other core ASes",
                      len(self._segs_to_prop))
        for pcbs in self._gen_prop_recs(self._segs_to_prop):
            self._propagate_to_core_ases(PathRecordsReply.from_values(pcbs))

    def _prop_to_master(self):
        assert not self.zk.have_lock()
        if not self._master_id:
            self._segs_to_master.clear()
            return
        if not self._segs_to_master:
            return
        logging.debug("Propagating %d segment(s) to master PS: %s",
                      len(self._segs_to_master), self._master_id)
        for pcbs in self._gen_prop_recs(self._segs_to_master):
            self._send_to_master(PathRecordsReply.from_values(pcbs))

    def _send_to_master(self, pld):
        """
        Send the payload to the master PS.
        """
        # XXX(kormat): Both of these should be very rare, as they are guarded
        # against in the two methods that call this one (_prop_to_master() and
        # _query_master(), but a race-condition could cause this to happen when
        # called from _query_master().
        if self.zk.have_lock():
            logging.warning("send_to_master: abandoning as we are master")
            return
        master = self._master_id
        if not master:
            logging.warning("send_to_master: abandoning as there is no master")
            return
        addr, port = master.addr(0)
        meta = self._build_meta(host=addr, port=port, reuse=True)
        self.send_meta(pld.copy(), meta)

    def _query_master(self, dst_ia, logger, src_ia=None, flags=()):
        """
        Query master for a segment.
        """
        if self.zk.have_lock() or not self._master_id:
            return
        src_ia = src_ia or self.addr.isd_as
        # XXX(kormat) Requests forwarded to the master CPS should be cache-only, as they only happen
        # in the case where a core segment is missing or a local down-segment is missing, and there
        # is nothing to query if the master CPS doesn't already have the information.
        # This has the side-effect of preventing query loops that could occur when two non-master
        # CPSes each believe the other is the master, for example.
        sflags = set(flags)
        sflags.add(PATH_FLAG_CACHEONLY)
        flags = tuple(sflags)
        req = PathSegmentReq.from_values(src_ia, dst_ia, flags=flags)
        logger.debug("Asking master (%s) for segment: %s" % (self._master_id, req.short_desc()))
        self._send_to_master(req)

    def _propagate_to_core_ases(self, rep_recs):
        """
        Propagate 'pkt' to other core ASes.
        """
        for isd_as in self._core_ases[self.addr.isd_as[0]]:
            if isd_as == self.addr.isd_as:
                continue
            csegs = self.core_segments(first_ia=isd_as,
                                       last_ia=self.addr.isd_as)
            if not csegs:
                logging.warning("Cannot propagate %s to AS %s. No path available." %
                                (rep_recs.NAME, isd_as))
                continue
            cseg = csegs[0].get_path(reverse_direction=True)
            meta = self._build_meta(ia=isd_as, path=cseg,
                                    host=SVCType.PS_A, reuse=True)
            self.send_meta(rep_recs.copy(), meta)

    def path_resolution(self, req, meta, new_request=True, logger=None):
        """
        Handle generic type of a path request.
        new_request informs whether a pkt is a new request (True), or is a
        pending request (False).
        Return True when resolution succeeded, False otherwise.
        """
        if logger is None:
            logger = self.get_request_logger(req, meta)
        dst_ia = req.dst_ia()
        if new_request:
            logger.info("PATH_REQ received")
        if dst_ia == self.addr.isd_as:
            logger.warning("Dropping request: requested DST is local AS")
            return False
        # dst as==0 means any core AS in the specified ISD
        dst_is_core = self.is_core_as(dst_ia) or dst_ia[1] == 0
        if dst_is_core:
            core_segs = self._resolve_core(
                req, meta, dst_ia, new_request, req.flags(), logger)
            down_segs = set()
        else:
            core_segs, down_segs = self._resolve_not_core(
                req, meta, dst_ia, new_request, req.flags(), logger)

        if not (core_segs | down_segs):
            if new_request:
                logger.debug("Segs to %s not found." % dst_ia)
            return False

        self._send_path_segments(req, meta, logger, core=core_segs, down=down_segs)
        return True

    def _resolve_core(self, req, meta, dst_ia, new_request, flags, logger):
        """
        Dst is core AS.
        """
        sibra = PATH_FLAG_SIBRA in flags
        params = {"last_ia": self.addr.isd_as}
        params["sibra"] = sibra
        params.update(dst_ia.params())
        core_segs = set(self.core_segments(**params))
        if not core_segs and new_request and PATH_FLAG_CACHEONLY not in flags:
            # Segments not found and it is a new request.
            self.pending_req[(dst_ia, sibra)].append((req, meta, logger))
            # If dst is in remote ISD then a segment may be kept by master.
            if dst_ia[0] != self.addr.isd_as[0]:
                self._query_master(dst_ia, logger, flags=flags)
        return core_segs

    def _resolve_not_core(self, seg_req, meta, dst_ia, new_request, flags, logger):
        """
        Dst is regular AS.
        """
        sibra = PATH_FLAG_SIBRA in flags
        core_segs = set()
        down_segs = set()
        # Check if there exists any down-segs to dst.
        tmp_down_segs = self.down_segments(last_ia=dst_ia, sibra=sibra)
        if not tmp_down_segs and new_request and PATH_FLAG_CACHEONLY not in flags:
            self._resolve_not_core_failed(seg_req, meta, dst_ia, flags, logger)

        for dseg in tmp_down_segs:
            dseg_ia = dseg.first_ia()
            if (dseg_ia == self.addr.isd_as or
                    seg_req.src_ia()[0] != self.addr.isd_as[0]):
                # If it's a direct down-seg, or if it's a remote query, there's
                # no need to include core-segs
                down_segs.add(dseg)
                continue
            # Now try core segments that connect to down segment.
            tmp_core_segs = self.core_segments(
                first_ia=dseg_ia, last_ia=self.addr.isd_as, sibra=sibra)
            if not tmp_core_segs and new_request and PATH_FLAG_CACHEONLY not in flags:
                # Core segment not found and it is a new request.
                self.pending_req[(dseg_ia, sibra)].append((seg_req, meta, logger))
                if dst_ia[0] != self.addr.isd_as[0]:
                    # Master may know a segment.
                    self._query_master(dseg_ia, logger, flags=flags)
            elif tmp_core_segs:
                down_segs.add(dseg)
                core_segs.update(tmp_core_segs)
        return core_segs, down_segs

    def _resolve_not_core_failed(self, seg_req, meta, dst_ia, flags, logger):
        """
        Execute after _resolve_not_core() cannot resolve a new request, due to
        lack of corresponding down segment(s).
        This must not be executed for a pending request.
        """
        sibra = PATH_FLAG_SIBRA in flags
        self.pending_req[(dst_ia, sibra)].append((seg_req, meta, logger))
        if dst_ia[0] == self.addr.isd_as[0]:
            # Master may know down segment as dst is in local ISD.
            self._query_master(dst_ia, logger, flags=flags)
            return

        # Dst is in a remote ISD, ask any core AS from there. Don't use a SIBRA
        # segment, even if the request has the SIBRA flag set, as this is just
        # for basic internal communication.
        csegs = self.core_segments(
            first_isd=dst_ia[0], last_ia=self.addr.isd_as)
        if csegs:
            cseg = csegs[0]
            path = cseg.get_path(reverse_direction=True)
            dst_ia = cseg.first_ia()
            logger.info("Down-Segment request for different ISD, "
                        "forwarding request to CPS in %s via %s" %
                        (dst_ia, cseg.short_desc()))
            meta = self._build_meta(ia=dst_ia, path=path,
                                    host=SVCType.PS_A, reuse=True)
            self.send_meta(seg_req, meta)
        else:
            # If no core segment was available, add request to waiting targets.
            logger.info("Waiting for core segment to ISD %s", dst_ia[0])
            self.waiting_targets[dst_ia[0]].append((seg_req, logger))
            # Ask for any segment to dst_isd
            self._query_master(dst_ia.any_as(), logger)

    def _forward_revocation(self, rev_info, meta):
        # Propagate revocation to other core ASes if:
        # 1) The revoked interface belongs to this AS, or
        # 2) the revocation was received from a non-core AS in this ISD, or
        # 3) the revocation was forked from a BR and it originated from a
        #    different ISD.
        rev_isd_as = rev_info.isd_as()
        if (rev_isd_as == self.addr.isd_as or
                (meta.ia not in self._core_ases[self.addr.isd_as[0]]) or
                (meta.ia == self.addr.isd_as and
                 rev_isd_as[0] != self.addr.isd_as[0])):
            logging.debug("Propagating revocation to other cores: %s"
                          % rev_info.short_desc())
            self._propagate_to_core_ases(rev_info)
