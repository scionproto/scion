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

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.crypto.hash_chain import HashChain
from lib.defines import PATH_SERVICE, SCION_UDP_PORT
from lib.errors import SCIONBaseError, SCIONServiceLookupError
from lib.packet.host_addr import haddr_parse
from lib.packet.path import EmptyPath, PathCombinator
from lib.packet.path_mgmt import PathSegmentInfo
from lib.packet.scion_addr import ISD_AD
from lib.path_db import PathSegmentDB
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.types import (
    AddrType,
    PathMgmtType as PMT,
    PathSegmentType as PST,
    PayloadClass,
)
from lib.util import update_dict

WAIT_CYCLES = 3
SCIOND_API_HOST = "127.255.255.254"
SCIOND_API_PORT = 3333


class SCIONDaemonBaseError(SCIONBaseError):
    """
    Base sciond error
    """
    pass


class SCIONDaemonPathLookupError(SCIONDaemonBaseError):
    """
    Path lookup failure
    """
    pass


class SCIONDaemon(SCIONElement):
    """
    The SCION Daemon used for retrieving and combining paths.

    :cvar TIMEOUT:
    :type TIMEOUT:
    :ivar up_segments:
    :type up_segments:
    :ivar down_segments:
    :type down_segments:
    :ivar core_segments:
    :type core_segments:
    :ivar _waiting_targets:
    :type _waiting_targets:
    :ivar _api_socket:
    :type _api_socket:
    :ivar _socks:
    :type _socks:
    """
    TIMEOUT = 5
    # Number of tokens the PS checks when receiving a revocation.
    N_TOKENS_CHECK = 20
    # Time a path segment is cached at a host (in seconds).
    SEGMENT_TTL = 300

    def __init__(self, conf_dir, addr, api_addr, run_local_api=False,
                 port=SCION_UDP_PORT, is_sim=False):
        """
        Initialize an instance of the class SCIONDaemon.
        """
        super().__init__("sciond", conf_dir, host_addr=addr, port=port,
                         is_sim=is_sim)
        # TODO replace by pathstore instance
        self.up_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL)
        self.down_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL)
        self.core_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL)
        self._waiting_targets = {PST.UP: {},
                                 PST.DOWN: {},
                                 PST.CORE: {},
                                 PST.UP_DOWN: {}}
        self._api_socket = None
        self.daemon_thread = None

        self.PLD_CLASS_MAP = {
            PayloadClass.PATH: {
                PMT.REPLY: self.handle_path_reply,
                PMT.REVOCATION: self.handle_revocation,
            }
        }
        if run_local_api:
            if not api_addr:
                api_addr = SCIOND_API_HOST
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
        sd = SCIONDaemon.start(addr, topo_file)
        paths = sd.get_paths(isd_id, ad_id)

        :param :
        :type :
        :param :
        :type :
        :param :
        :type :
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
        logging.debug("Stopping SCIONDaemon")
        super().stop()
        self.daemon_thread.join()

    def _request_paths(self, ptype, dst_isd, dst_ad, src_isd=None, src_ad=None,
                       requester=None):
        """
        Send a path request of a certain type for an (isd, ad).
        The requester argument holds the address of requester. Used in simulator
        to send path reply.

        :param ptype:
        :type ptype:
        :param dst_isd: destination ISD identifier.
        :type dst_isd: int
        :param dst_ad: destination AD identifier.
        :type dst_ad: int
        :param src_isd: source ISD identifier.
        :type src_isd: int
        :param src_ad: source AD identifier.
        :type src_ad: int
        :param requester: Path requester address(used in simulator).
        :type requester:
        :raises:
            SCIONDaemonPathLookupError: if paths request fails
        """
        if src_isd is None:
            src_isd = self.topology.isd_id
        if src_ad is None:
            src_ad = self.topology.ad_id
        # Lookup the path server at the start, so if this fails, we don't do any
        # more setup.
        try:
            dst = self.dns_query_topo(PATH_SERVICE)[0]
        except SCIONServiceLookupError as e:
            raise SCIONDaemonPathLookupError(e) from None
        # Create a semaphore that we can wait on for the path reply.
        sema = threading.Semaphore(value=0)
        update_dict(self._waiting_targets[ptype], (dst_isd, dst_ad), [sema])
        # Create and send out path request.
        info = PathSegmentInfo.from_values(ptype, src_isd, src_ad, dst_isd,
                                           dst_ad)
        path_request = self._build_packet(dst, payload=info)
        self.send(path_request, dst)
        # Wait for path reply and clear us from the waiting list when we got it.
        cycle_cnt = 0
        while cycle_cnt < WAIT_CYCLES:
            sema.acquire(timeout=self.TIMEOUT)
            # Check that we got all the requested paths.
            if ((ptype == PST.UP and len(self.up_segments)) or
                (ptype == PST.DOWN and
                 self.down_segments(last_isd=dst_isd, last_ad=dst_ad)) or
                (ptype == PST.CORE and
                 self.core_segments(last_isd=src_isd, last_ad=src_ad,
                                    first_isd=dst_isd, first_ad=dst_ad)) or
                (ptype == PST.UP_DOWN and (len(self.up_segments) and
                 self.down_segments(last_isd=dst_isd, last_ad=dst_ad)))):
                self._waiting_targets[ptype][(dst_isd, dst_ad)].remove(sema)
                del self._waiting_targets[ptype][(dst_isd, dst_ad)]
                break
            cycle_cnt += 1

    def get_paths(self, dst_isd, dst_ad, requester=None):
        """
        Return a list of paths.
        The requester argument holds the address of requester. Used in simulator
        to send path reply.

        :param dst_isd: ISD identifier.
        :type dst_isd: int
        :param dst_ad: AD identifier.
        :type dst_ad: int
        :param requester: Path requester address(used in simulator).
        :type requester:
        :raises:
            SCIONDaemonPathLookupError: if paths lookup fail
        """
        # Handle request to local AS.
        if self.addr.get_isd_ad() == (dst_isd, dst_ad):
            return [EmptyPath()]
        full_paths = []
        self._request_paths(PST.UP_DOWN, dst_isd, dst_ad, requester=requester)
        down_segments = self.down_segments(last_isd=dst_isd, last_ad=dst_ad)
        if len(self.up_segments) and down_segments:
            full_paths = PathCombinator.build_shortcut_paths(self.up_segments(),
                                                             down_segments)
            src_isd = self.topology.isd_id
            core_segments = []
            src_dst_sets = set()
            for us in self.up_segments():
                src_core_ad = us.get_first_pcbm().ad_id
                for ds in down_segments:
                    dst_core_ad = ds.get_first_pcbm().ad_id
                    key = (src_isd, src_core_ad, dst_isd, dst_core_ad)
                    if key in src_dst_sets:
                        continue
                    if (src_isd, src_core_ad) == (dst_isd, dst_core_ad):
                        continue
                    self._request_paths(PST.CORE, dst_isd, dst_core_ad,
                                        src_ad=src_core_ad, requester=requester)
                    cs = self.core_segments(last_isd=src_isd,
                                            last_ad=src_core_ad,
                                            first_isd=dst_isd,
                                            first_ad=dst_core_ad)
                    src_dst_sets.add(key)
                    core_segments.extend(cs)

            for us in self.up_segments():
                for ds in down_segments:
                    full_paths.extend(PathCombinator.build_core_paths(
                        us, ds, core_segments))

        return full_paths

    def handle_path_reply(self, pkt):
        """
        Handle path reply from local path server.

        :param path_reply:
        :type path_reply:
        """
        path_reply = pkt.get_payload()
        info = path_reply.info
        for pcb in path_reply.pcbs:
            isd = pcb.get_isd()
            ad = pcb.get_last_pcbm().ad_id
            if ((self.topology.isd_id != isd or self.topology.ad_id != ad)
                    and info.seg_type in [PST.DOWN, PST.UP_DOWN]
                    and info.dst_isd == isd and info.dst_ad == ad):
                self.down_segments.update(pcb, info.src_isd, info.src_ad,
                                          info.dst_isd, info.dst_ad)
                logging.debug("Down path added: %s", pcb.short_desc())
            elif ((self.topology.isd_id == isd and self.topology.ad_id == ad)
                    and info.seg_type in [PST.UP, PST.UP_DOWN]):
                self.up_segments.update(pcb, pcb.get_isd(),
                                        pcb.get_first_pcbm().ad_id, isd, ad)
                logging.debug("Up path added: %s", pcb.short_desc())
            elif info.seg_type == PST.CORE:
                self.core_segments.update(pcb, info.dst_isd, info.dst_ad,
                                          info.src_isd, info.src_ad)
                logging.debug("Core path added: %s", pcb.short_desc())
            else:
                logging.warning("Incorrect path in Path Record")
        self.handle_waiting_targets(path_reply)

    def handle_waiting_targets(self, path_reply):
        """
        Handles waiting request from path reply

        :param path_reply:
        :type path_reply:
        """
        info = path_reply.info
        # Wake up sleeping get_paths().
        if (info.dst_isd, info.dst_ad) in self._waiting_targets[info.seg_type]:
            for sema in self._waiting_targets[info.seg_type][(info.dst_isd,
                                                              info.dst_ad)]:
                sema.release()

    def _api_handle_path_request(self, packet, sender):
        """
        Path request:
          | \x00 (1B) | ISD (12bits) |  AD (20bits)  |
        Reply:
          |p1_len(1B)|p1((p1_len*8)B)|fh_IP(4B)|fh_port(2B)|
           p1_if_count(1B)|p1_if_1(5B)|...|p1_if_n(5B)|
           p2_len(1B)|...
         or b"" when no path found. Only IPv4 supported currently.

        FIXME(kormat): make IP-version independant

        :param packet:
        :type packet:
        :param sender:
        :type sender:
        """
        (isd, ad) = ISD_AD.from_raw(packet[1:ISD_AD.LEN + 1])
        try:
            paths = self.get_paths(isd, ad)
        except SCIONDaemonPathLookupError as e:
            logging.error("Path lookup failure: %s", e)
            paths = []
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
                         struct.pack("B", len(path.interfaces)))
            for interface in path.interfaces:
                (isd_ad, link) = interface
                isd_ad_bits = (isd_ad.isd << 20) + (isd_ad.ad & 0xFFFFF)
                reply.append(struct.pack("I", isd_ad_bits))
                reply.append(struct.pack("B", link))
        self._api_sock.send(b"".join(reply), sender)

    def api_handle_request(self, packet, sender):
        """
        Handle local API's requests.

        :param packet:
        :type packet:
        :param sender:
        :type sender:
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

    def handle_request(self, packet, sender, from_local_socket=True):
        # PSz: local_socket may be misleading, especially that we have
        # api_socket which is local (in the localhost sense). What do you think
        # about changing local_socket to ad_socket
        """
        Main routine to handle incoming SCION packets.

        :param packet:
        :type packet:
        :param sender:
        :type sender:
        :param from_local_socket:
        :type from_local_socket:
        """
        if not from_local_socket:  # From localhost (SCIONDaemon API)
            self.api_handle_request(packet, sender)
            return
        super().handle_request(packet, sender, from_local_socket)
