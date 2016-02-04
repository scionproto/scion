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
from lib.log import log_exception
from lib.packet.host_addr import haddr_parse
from lib.packet.path import EmptyPath, PathCombinator
from lib.packet.path_mgmt import PathSegmentInfo
from lib.packet.scion_addr import ISD_AD
from lib.path_db import PathSegmentDB
from lib.requests import RequestHandler
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
        self._in_core = self.addr.get_isd_ad() in self._core_ads[
            self.addr.isd_id]

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
        paths = sd.get_paths(isd_id, ad_id)
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
        # about changing local_socket to ad_socket
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
        added = set()  # Set of added destinations.
        path_reply = pkt.get_payload()
        for seg_type, pcbs in path_reply.pcbs.items():
            for pcb in pcbs:
                first = pcb.get_first_pcbm()
                last = pcb.get_last_pcbm()
                if seg_type == PST.UP:
                    self._handle_up_seg(pcb, first, last)
                    added.add(first.get_isd_ad())
                elif seg_type == PST.DOWN:
                    self._handle_down_seg(pcb, first, last)
                    added.add(last.get_isd_ad())
                elif seg_type == PST.CORE:
                    self._handle_core_seg(pcb, first, last)
                    added.add(first.get_isd_ad())
                else:
                    logging.warning(
                        "Incorrect path in Path Record. Type: %s PCB: %s",
                        seg_type, pcb.short_desc())
        for key in added:
            self.requests.put((key, None))

    def _handle_up_seg(self, pcb, first, last):
        if self.addr.get_isd_ad() != (last.isd_id, last.ad_id):
            return
        self.up_segments.update(pcb, first.isd_id, first.ad_id,
                                last.isd_id, last.ad_id)
        logging.debug("Up path added: %s", pcb.short_desc())

    def _handle_down_seg(self, pcb, first, last):
        if self.addr.get_isd_ad() == (last.isd_id, last.ad_id):
            return
        self.down_segments.update(pcb, first.isd_id, first.ad_id,
                                  last.isd_id, last.ad_id)
        logging.debug("Down path added: %s", pcb.short_desc())

    def _handle_core_seg(self, pcb, first, last):
        self.core_segments.update(pcb, first.isd_id, first.ad_id,
                                  last.isd_id, last.ad_id)
        logging.debug("Core path added: %s", pcb.short_desc())

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
          | \x00 (1B) | ISD (12bits) |  AD (20bits)  |
        Reply:
          |p1_len(1B)|p1((p1_len*8)B)|fh_IP(4B)|fh_port(2B)|mtu(2B)|
           p1_if_count(1B)|p1_if_1(5B)|...|p1_if_n(5B)|
           p2_len(1B)|...
         or b"" when no path found. Only IPv4 supported currently.

        FIXME(kormat): make IP-version independant
        """
        isd, ad = ISD_AD.from_raw(packet[1:ISD_AD.LEN + 1])
        paths = self.get_paths(isd, ad)
        reply = []
        for path in paths:
            raw_path = path.pack()
            # assumed IPv4 addr
            fwd_if = path.get_fwd_if()
            # Set dummy host addr if path is EmptyPath.
            # TODO(PSz): remove dummy "0.0.0.0" address when API is saner
            haddr = self.ifid2addr.get(fwd_if, haddr_parse("IPV4", "0.0.0.0"))
            path_len = len(raw_path) // 8
            reply.append(struct.pack("B", path_len) + raw_path +
                         haddr.pack() + struct.pack("H", SCION_UDP_PORT) +
                         struct.pack("H", path.mtu) +
                         struct.pack("B", len(path.interfaces)))
            for interface in path.interfaces:
                (isd_ad, link) = interface
                isd_ad_bits = (isd_ad.isd << 20) + (isd_ad.ad & 0xFFFFF)
                reply.append(struct.pack("I", isd_ad_bits))
                reply.append(struct.pack("H", link))
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

    def get_paths(self, dst_isd, dst_ad, requester=None):
        """
        Return a list of paths.
        The requester argument holds the address of requester. Used in simulator
        to send path reply.

        :param int dst_isd: ISD identifier.
        :param int dst_ad: AD identifier.
        :param requester: Path requester address(used in simulator).
        """
        key = dst_isd, dst_ad
        logging.debug("Paths requested for %s", key)
        if self.addr.isd_id == dst_isd:
            if self.addr.ad_id == dst_ad or (self._in_core and not dst_ad):
                return [EmptyPath()]
        deadline = SCIONTime.get_time() + self.TIMEOUT
        e = threading.Event()
        self.requests.put((key, e))
        if not self._wait_for_events([e], deadline):
            logging.error("Query timed out for %s", key)
            return []
        return self.path_resolution(dst_isd, dst_ad)

    def path_resolution(self, dst_isd, dst_ad):
        # dst_ad = 0 means any core AS in the specified ISD.
        dst_is_core = (
            (dst_isd, dst_ad) in self._core_ads[dst_isd] or not dst_ad)
        if self._in_core:
            return self._resolve_core(dst_isd, dst_ad, dst_is_core)
        elif dst_is_core:  # I'm non core AS, but dst is core.
            return self._resolve_not_core_core(dst_isd, dst_ad)
        else:  # Me and dst are non-core.
            return self._resolve_not_core_not_core(dst_isd, dst_ad)

    def _resolve_core(self, dst_isd, dst_ad, dst_is_core):
        """
        I'm within core AS.
        """
        res = set()
        my_isd, my_ad = self.addr.get_isd_ad()
        if dst_is_core:
            my_isd, my_ad = self.addr.get_isd_ad()
            params = {"last_isd": my_isd, "last_ad": my_ad,
                      "first_isd": dst_isd}
            if dst_ad:
                # dst_ad=0 means any core AS in the specified ISD, so only
                # filter on the remote AS if it isn't 0
                params["first_ad"] = dst_ad
            for cseg in self.core_segments(**params):
                res.add((None, cseg, None))
            return PathCombinator.tuples_to_full_paths(res)

        # Dst is non core AS.
        # First check whether there is a direct path.
        for dseg in self.down_segments(first_isd=my_isd, first_ad=my_ad,
                                       last_isd=dst_isd, last_ad=dst_ad):
            res.add((None, None, dseg))
        # Check core-down combination.
        for dseg in self.down_segments(last_isd=dst_isd, last_ad=dst_ad):
            isd, ad = dseg.get_first_isd_ad()
            if (my_isd, my_ad) == (isd, ad):
                pass
            for cseg in self.core_segments(first_isd=isd, first_ad=ad,
                                           last_isd=my_isd, last_ad=my_ad):
                res.add((None, cseg, dseg))
        return PathCombinator.tuples_to_full_paths(res)

    def _resolve_not_core_core(self, dst_isd, dst_ad):
        """
        I'm within non-core AS, but dst is within core AS.
        """
        res = set()
        params = {"first_isd": dst_isd}
        if dst_ad:
            # dst_ad=0 means any core AS in the specified ISD, so only filter
            # on AS when dst_ad is not 0.
            params["first_ad"] = dst_ad
        if dst_isd == self.addr.isd_id:
            # Dst in local ISD. First check whether DST is a (super)-parent.
            for useg in self.up_segments(**params):
                res.add((useg, None, None))
        # Check whether dst is known core AS.
        for cseg in self.core_segments(**params):
            # Check do we have an up-seg that is connected to core_seg.
            isd, ad = cseg.get_last_isd_ad()
            for useg in self.up_segments(first_isd=isd, first_ad=ad):
                res.add((useg, cseg, None))
        return PathCombinator.tuples_to_full_paths(res)

    def _resolve_not_core_not_core(self, dst_isd, dst_ad):
        """
        I'm within non-core AS and dst is within non-core AS.
        """
        up_segs = self.up_segments()
        down_segs = self.down_segments(last_isd=dst_isd, last_ad=dst_ad)
        core_segs, _ = self._calc_core_segs(dst_isd, up_segs, down_segs)
        full_paths = PathCombinator.build_shortcut_paths(up_segs, down_segs)
        for up_seg in up_segs:
            for down_seg in down_segs:
                full_paths.extend(PathCombinator.build_core_paths(
                    up_seg, down_seg, core_segs))
        return full_paths

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
        dst_isd, dst_ad = key
        return self.path_resolution(dst_isd, dst_ad)

    def _fetch_segments(self, key, _):
        """
        Called by RequestHandler to fetch the requested path.
        """
        dst_isd, dst_ad = key
        my_isd, my_ad = self.addr.get_isd_ad()
        try:
            ps = self.dns_query_topo(PATH_SERVICE)[0]
        except SCIONServiceLookupError:
            log_exception("Error querying path service:")
            return
        info = PathSegmentInfo.from_values(PST.GENERIC, my_isd,
                                           my_ad, dst_isd, dst_ad)
        logging.debug("Sending path request: %s", info.short_desc())
        path_request = self._build_packet(ps, payload=info)
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
        dst_isd, dst_ad = key
        ret = []
        for rk in req_keys:
            if (rk == key) or (rk == (key[0], 0)):
                # Covers the case where a request was for ISD,0 (i.e. any path
                # to a core AS in the specified ISD)
                ret.append(rk)
        return ret

    def _calc_core_segs(self, dst_isd, up_segs, down_segs):
        """
        Calculate all possible core segments joining the provided up and down
        segments. Returns a list of all known segments, and a seperate list of
        the missing AD pairs.
        """
        src_core_ads = set()
        dst_core_ads = set()
        for seg in up_segs:
            src_core_ads.add(seg.get_first_pcbm().ad_id)
        for seg in down_segs:
            dst_core_ads.add(seg.get_first_pcbm().ad_id)
        # Generate all possible AD pairs
        ad_pairs = list(product(src_core_ads, dst_core_ads))
        return self._find_core_segs(self.addr.isd_id, dst_isd, ad_pairs)

    def _find_core_segs(self, src_isd, dst_isd, ad_pairs):
        """
        Given a set of AD pairs across 2 ISDs, return the core segments
        connecting those pairs, and a list of AD pairs for which a core segment
        wasn't found.
        """
        core_segs = []
        missing = []
        for src_core_ad, dst_core_ad in ad_pairs:
            if (src_isd, src_core_ad) == (dst_isd, dst_core_ad):
                continue
            seg = self.core_segments(
                last_isd=src_isd, last_ad=src_core_ad,
                first_isd=dst_isd, first_ad=dst_core_ad)
            if seg:
                core_segs.extend(seg)
            else:
                missing.append((src_core_ad, dst_core_ad))
        return core_segs, missing
