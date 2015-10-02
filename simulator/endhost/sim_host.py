# Copyright 2015 ETH Zurich
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
:mod:`sim_host` --- SCION Host for Simulator
============================================
"""
# Stdlib
import logging
import struct

# SCION
from endhost.sciond import SCIONDaemon, SCIOND_API_PORT
from lib.defines import SCION_UDP_PORT
from lib.errors import SCIONBaseError, SCIONParseError
from lib.log import log_exception
from lib.packet.packet_base import PayloadClass
from lib.packet.path import PathCombinator
from lib.packet.path_mgmt import (
    PathMgmtType as PMT,
    PathSegmentInfo,
    PathSegmentType as PST,
)
from lib.packet.scion import SCIONL4Packet
from lib.packet.scion_addr import ISD_AD
from lib.util import update_dict

# External
from itertools import count


class SCIONSimHost(SCIONDaemon):
    """
    The SCION Simulator endhost. Applications can be simulated on this host
    """
    def __init__(self, addr, topo_file, simulator):
        """
        Initializes SimHost by calling constructor of SCIONDaemon with
        is_sim variable set to True

        :param addr:
        :type addr:
        :param topo_file:
        :type topo_file:
        :param run_local_api:
        :type run_local_api:
        :param simulator: Instance of simulator class.
        :type simulator: Simulator
        """
        SCIONDaemon.__init__(self, addr, topo_file, is_sim=True)
        self.simulator = simulator
        simulator.add_element(str(self.addr.host_addr), self)
        self.apps = {}
        self._waiting_requests = []
        self.request_id = count()

    def add_application(self, app, port, run_cb, recv_cb, path_cb):
        """
        Add an application on this host
        """
        self.apps[port] = (app, run_cb, recv_cb, path_cb)

    def run(self):
        """
        Run the callback - run_cb of all applications running on this host
        """
        for port in self.apps:
            _, run_cb, _, _ = self.apps[port]
            run_cb()

    def _expire_request_timeout(self, ptype, requester):
        """
        Path request timed out. Send back an empty reply.
        """
        logging.warning("Request timed out %s, %s", ptype, requester)
        req_id = requester[2]
        # Path reply is already sent
        if self._waiting_requests.count(req_id) == 0:
            return
        _, _, _, path_cb = self.apps[requester[1]]
        path_cb(b"")

    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        self.simulator.add_event(0., dst=str(dst),
                                 args=(packet.pack(),
                                       (str(self.addr), SCION_UDP_PORT),
                                       (str(dst), dst_port)))

    def clean(self):
        pass

    def _request_paths(self, ptype, dst_isd, dst_ad, src_isd=None,
                       src_ad=None, requester=None):
        """
        Sends path request with certain type for (isds, ad).

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
        :param requester: [Host address, Application port, request id]
        :type requester: [IPv4Address, int, int]
        """
        if src_isd is None:
            src_isd = self.topology.isd_id
        if src_ad is None:
            src_ad = self.topology.ad_id
        eid = self.simulator.add_event(3 * self.TIMEOUT,
                                       cb=self._expire_request_timeout,
                                       args=(ptype, requester))
        update_dict(self._waiting_targets[ptype], (dst_isd, dst_ad),
                    [(eid, requester)])
        # Create and send out path request.
        info = PathSegmentInfo.from_values(ptype, src_isd, src_ad, dst_isd,
                                           dst_ad)
        dst = self.topology.path_servers[0].addr
        path_request = self._build_packet(dst, payload=info)
        self.send(path_request, dst)

    def _get_full_paths(self, src_isd, src_ad, dst_isd, dst_ad,
                        src_core_ad=None, dst_core_ad=None):
        """
        Combines up-paths, core-paths and down-paths to get a full path
        """
        full_paths = []
        if src_core_ad is None and dst_core_ad is None:
            down_segments = self.down_segments(last_isd=dst_isd, last_ad=dst_ad)
            if len(self.up_segments) and down_segments:
                full_paths = PathCombinator.build_shortcut_paths(
                    self.up_segments(), down_segments)
            if full_paths:
                return full_paths
        if src_core_ad is None or dst_core_ad is None:
            return None
        core_segments = self.core_segments(last_isd=src_isd,
                                           last_ad=src_core_ad,
                                           first_isd=dst_isd,
                                           first_ad=dst_core_ad)
        logging.debug("(%d, %d)->(%d, %d)", src_isd, src_ad, dst_isd, dst_ad)
        if core_segments:
            up_segment = []
            for segment in self.up_segments():
                if segment.get_first_pcbm().ad_id == src_core_ad:
                    up_segment = segment
                    break
            down_segment = []
            for segment in self.down_segments():
                if segment.get_first_pcbm().ad_id == dst_core_ad:
                    down_segment = segment
                    break
            if up_segment and down_segment:
                full_paths = PathCombinator.build_core_paths(
                    up_segment, down_segment, core_segments)

        return full_paths

    def handle_waiting_targets(self, path_reply):
        """
        Handles waiting request from path reply

        :param path_reply:
        :type path_reply:
        """
        info = path_reply.info
        if (info.dst_isd, info.dst_ad) in self._waiting_targets[info.seg_type]:
            for (eid, requester) in \
                    self._waiting_targets[info.seg_type][(info.dst_isd,
                                                         info.dst_ad)]:
                src_isd = self.topology.isd_id
                src_ad = self.topology.ad_id
                dst_isd = info.dst_isd
                dst_ad = info.dst_ad
                dst_isd_ad = (dst_isd, dst_ad)
                event = (eid, requester)

                if info.seg_type == PST.UP_DOWN:
                    full_paths = self._get_full_paths(src_isd, src_ad,
                                                      dst_isd, dst_ad)
                    down_segments = self.down_segments(last_isd=dst_isd,
                                                       last_ad=dst_ad)
                    if self.up_segments and down_segments:
                        self.simulator.remove_event(eid)
                        self._waiting_targets[info.seg_type][dst_isd_ad]\
                            .remove(event)
                    else:
                        continue

                    if not full_paths:
                        src_core_ad = \
                            self.up_segments()[0].get_first_pcbm().ad_id
                        dst_core_ad = \
                            down_segments[0].get_first_pcbm().ad_id
                        self._request_paths(PST.CORE, dst_isd, dst_core_ad,
                                            src_ad=src_core_ad,
                                            requester=requester)
                        continue
                elif info.seg_type == PST.CORE:
                    src_core_ad = info.src_ad
                    dst_core_ad = info.dst_ad
                    full_paths = self._get_full_paths(src_isd, src_ad,
                                                      dst_isd, dst_ad,
                                                      src_core_ad, dst_core_ad)
                    if self.core_segments(last_isd=src_isd,
                                          last_ad=src_core_ad,
                                          first_isd=dst_isd,
                                          first_ad=dst_core_ad):
                        self.simulator.remove_event(eid)
                        self._waiting_targets[info.seg_type][dst_isd_ad]\
                            .remove(event)
                    else:
                        continue

                    if not full_paths:
                        # TODO What action to be taken?
                        continue
                elif ((info.seg_type == PST.UP and self.up_segments) or
                      (info.seg_type == PST.DOWN and
                       self.down_segments(last_isd=dst_isd, last_ad=dst_ad))):
                    full_paths = self._get_full_paths(src_isd, src_ad,
                                                      dst_isd, dst_ad)
                    self.simulator.remove_event(eid)
                    self._waiting_targets[info.seg_type][dst_isd_ad]\
                        .remove(event)
                    if not full_paths:
                        # TODO What action to be taken?
                        continue
                self._api_send_path_reply(full_paths, requester)
            if len(self._waiting_targets[info.seg_type]
                   [(info.dst_isd, info.dst_ad)]) == 0:
                del self._waiting_targets[info.seg_type][dst_isd_ad]

    def _api_send_path_reply(self, paths, requester):
        """
        Send path reply to the requester
        """
        req_id = requester[2]
        # Case where reply is already sent
        if self._waiting_requests.count(req_id) == 0:
            logging.info("Request already handled")
            return
        # Remove from waiting requests
        self._waiting_requests.remove(req_id)
        reply = []
        for path in paths:
            raw_path = path.pack()
            # assumed IPv4 addr
            haddr = self.ifid2addr[path.get_fwd_if()]
            path_len = len(raw_path) // 8  # Check whether 8 divides path_len?
            reply.append(struct.pack("B", path_len) + raw_path + haddr.pack())
        _, _, _, path_cb = self.apps[requester[1]]
        path_cb(b"".join(reply))

    def _api_handle_path_request(self, packet, sender):
        """
        Path request:
          | \x00 (1B) | ISD (2B) |  AD (8B)  |
        Reply:
          |path1_len(1B)|path1(path1_len*8B)|first_hop_IP(4B)|path2_len(1B)...
         or b"" when no path found. Only IPv4 supported currently.

        :param packet:
        :type packet:
        :param sender:
        :type sender:
        """
        # TODO sanity checks
        (isd, ad) = ISD_AD.from_raw(packet[1:ISD_AD.LEN + 1])
        logging.info("Request for %d, %d", isd, ad)
        # Generate a request id
        req_id = next(self.request_id)
        self._waiting_requests.append(req_id)
        requester = list(sender)
        requester.append(req_id)
        full_paths = self.get_paths(isd, ad, requester=requester)
        if full_paths:
            self._api_send_path_reply(full_paths, requester)
            return

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
            self._api_handle_path_request(packet, sender)
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
        logging.warning("Unable to send packet due to revocation")
        app_port = pkt.l4_hdr.dst_port
        _, _, recv_cb, _ = self.apps[app_port]
        # TODO: src and dst not properly set
        # For now using recv_cb to send the revocation message
        recv_cb(pkt.pack(), None, None)

    def sim_recv(self, packet, src, dst):
        """
        The receive function called when simulator receives a packet
        """
        if dst[1] == SCIOND_API_PORT:  # From localhost (SCIONDaemon API)
            self.api_handle_request(packet, src)
            return
        type_map = {
            PMT.REPLY: self.handle_path_reply,
            PMT.REVOCATION: self.handle_revocation,
        }
        pkt = SCIONL4Packet(packet)
        try:
            payload = pkt.parse_payload()
        except SCIONParseError:
            if dst[1] not in self.apps:
                logging.error("Application %d not supported.", dst[1])
            else:
                assert dst[0] == str(self.addr.host_addr)
                _, _, recv_cb, _ = self.apps[dst[1]]
                recv_cb(packet, src, dst)
            return
        handler = type_map.get(payload.PAYLOAD_TYPE)
        if handler is None:
            logging.warning("Path management packet type %d not supported.",
                            payload.PAYLOAD_TYPE)
            return
        try:
            handler(pkt)
        except SCIONBaseError:
            log_exception("Error handling packet: %s" % pkt)
