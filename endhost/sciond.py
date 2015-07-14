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
import socket
import struct
import threading

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.packet.path import PathCombinator
from lib.packet.path_mgmt import (
    PathMgmtPacket,
    PathMgmtType as PMT,
    PathSegmentInfo,
    PathSegmentType as PST,
)
from lib.packet.scion_addr import ISD_AD
from lib.path_db import PathSegmentDB
from lib.util import update_dict

WAIT_CYCLES = 3
SCIOND_API_HOST = "127.255.255.254"
SCIOND_API_PORT = 3333


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
    :ivar _sockets:
    :type _sockets:
    """
    TIMEOUT = 5

    def __init__(self, addr, topo_file, run_local_api=False, is_sim=False):
        """
        Initialize an instance of the class SCIONDaemon.

        :param addr:
        :type addr:
        :param topo_file:
        :type topo_file:
        :param run_local_api:
        :type run_local_api:
        :param is_sim: running on simulator
        :type is_sim: bool
        """
        SCIONElement.__init__(self, "sciond", topo_file, host_addr=addr,
                              is_sim=is_sim)
        # TODO replace by pathstore instance
        self.up_segments = PathSegmentDB()
        self.down_segments = PathSegmentDB()
        self.core_segments = PathSegmentDB()
        self._waiting_targets = {PST.UP: {},
                                 PST.DOWN: {},
                                 PST.CORE: {},
                                 PST.UP_DOWN: {}}
        self._api_socket = None
        if run_local_api:
            self._api_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._api_socket.setsockopt(socket.SOL_SOCKET,
                                        socket.SO_REUSEADDR, 1)
            self._api_socket.bind((SCIOND_API_HOST, SCIOND_API_PORT))
            self._sockets.append(self._api_socket)
            logging.info("Local API %s:%u", SCIOND_API_HOST, SCIOND_API_PORT)

    @classmethod
    def start(cls, addr, topo_file, run_local_api=False):
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
        sd = cls(addr, topo_file, run_local_api)
        t = threading.Thread(target=sd.run)
        t.setDaemon(True)
        t.start()
        return sd

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
        """
        if src_isd is None:
            src_isd = self.topology.isd_id
        if src_ad is None:
            src_ad = self.topology.ad_id
        # Create an event that we can wait on for the path reply.
        event = threading.Event()
        update_dict(self._waiting_targets[ptype], (dst_isd, dst_ad), [event])
        # Create and send out path request.
        info = PathSegmentInfo.from_values(ptype, src_isd, dst_isd,
                                           src_ad, dst_ad)
        path_request = PathMgmtPacket.from_values(PMT.REQUEST, info,
                                                  None, self.addr,
                                                  ISD_AD(src_isd, src_ad))
        dst = self.topology.path_servers[0].addr
        self.send(path_request, dst)
        # Wait for path reply and clear us from the waiting list when we got it.
        cycle_cnt = 0
        while cycle_cnt < WAIT_CYCLES:
            event.wait(SCIONDaemon.TIMEOUT)
            # Check that we got all the requested paths.
            if ((ptype == PST.UP and len(self.up_segments)) or
                (ptype == PST.DOWN and
                 self.down_segments(dst_isd=dst_isd, dst_ad=dst_ad)) or
                (ptype == PST.CORE and
                 self.core_segments(src_isd=src_isd, src_ad=src_ad,
                                    dst_isd=dst_isd, dst_ad=dst_ad)) or
                (ptype == PST.UP_DOWN and (len(self.up_segments) and
                 self.down_segments(dst_isd=dst_isd, dst_ad=dst_ad)))):
                self._waiting_targets[ptype][(dst_isd, dst_ad)].remove(event)
                del self._waiting_targets[ptype][(dst_isd, dst_ad)]
                break
            event.clear()
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
        """
        full_paths = []
        down_segments = self.down_segments(dst_isd=dst_isd, dst_ad=dst_ad)
        # Fetch down-paths if necessary.
        if not down_segments:
            self._request_paths(PST.UP_DOWN, dst_isd, dst_ad,
                                requester=requester)
            down_segments = self.down_segments(dst_isd=dst_isd, dst_ad=dst_ad)
        if len(self.up_segments) and down_segments:
            full_paths = PathCombinator.build_shortcut_paths(self.up_segments(),
                                                             down_segments)
            if full_paths:
                return full_paths
            else:
                # No shortcut path could be built. Select an up and down path
                # and request a set of core-paths connecting them.
                # For now we just choose the first up-/down-path.
                # TODO: Atm an application can't choose the up-/down-path to be
                #       be used. Discuss with Pawel.
                src_isd = self.topology.isd_id
                src_core_ad = self.up_segments()[0].get_first_pcbm().ad_id
                dst_core_ad = down_segments[0].get_first_pcbm().ad_id
                core_segments = self.core_segments(src_isd=src_isd,
                                                   src_ad=src_core_ad,
                                                   dst_isd=dst_isd,
                                                   dst_ad=dst_core_ad)
                if ((src_isd, src_core_ad) != (dst_isd, dst_core_ad) and
                        not core_segments):
                    self._request_paths(PST.CORE, dst_isd, dst_core_ad,
                                        src_ad=src_core_ad,
                                        requester=requester)
                    core_segments = self.core_segments(src_isd=src_isd,
                                                       src_ad=src_core_ad,
                                                       dst_isd=dst_isd,
                                                       dst_ad=dst_core_ad)
                full_paths = PathCombinator.build_core_paths(
                    self.up_segments()[0],
                    down_segments[0],
                    core_segments)
        return full_paths

    def handle_path_reply(self, path_reply):
        """
        Handle path reply from local path server.

        :param path_reply:
        :type path_reply:
        """
        info = path_reply.info
        for pcb in path_reply.pcbs:
            isd = pcb.get_isd()
            ad = pcb.get_last_pcbm().ad_id
            if ((self.topology.isd_id != isd or self.topology.ad_id != ad)
                    and info.type in [PST.DOWN, PST.UP_DOWN]
                    and info.dst_isd == isd and info.dst_ad == ad):
                self.down_segments.update(pcb, info.src_isd, info.src_ad,
                                          info.dst_isd, info.dst_ad)
                logging.info("Down path (%d, %d)->(%d, %d) added.",
                             info.src_isd, info.src_ad, info.dst_isd,
                             info.dst_ad)
            elif ((self.topology.isd_id == isd and self.topology.ad_id == ad)
                    and info.type in [PST.UP, PST.UP_DOWN]):
                self.up_segments.update(pcb, isd, ad, pcb.get_isd(),
                                        pcb.get_first_pcbm().ad_id)
                logging.info("Up path (%d, %d)->(%d, %d) added.",
                             info.src_isd, info.src_ad, info.dst_isd,
                             info.dst_ad)
            elif info.type == PST.CORE:
                self.core_segments.update(pcb, info.src_isd, info.src_ad,
                                          info.dst_isd, info.dst_ad)
                logging.info("Core path (%d, %d)->(%d, %d) added.",
                             info.src_isd, info.src_ad, info.dst_isd,
                             info.dst_ad)
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
        if (info.dst_isd, info.dst_ad) in self._waiting_targets[info.type]:
            for event in self._waiting_targets[info.type][(info.dst_isd,
                                                           info.dst_ad)]:
                event.set()

    def _api_handle_path_request(self, packet, sender):
        """
        Path request:
          | \x00 (1B) | ISD (12bits) |  AD (20bits)  |
        Reply:
          |path1_len(1B)|path1(path1_len*8B)|first_hop_IP(4B)|path2_len(1B)...
         or b"" when no path found. Only IPv4 supported currently.

        :param packet:
        :type packet:
        :param sender:
        :type sender:
        """
        (isd, ad) = ISD_AD.from_raw(packet[1:ISD_AD.LEN + 1])
        paths = self.get_paths(isd, ad)
        reply = []
        for path in paths:
            raw_path = path.pack()
            # assumed IPv4 addr
            if path.get_first_info_of().up_flag:
                hop = self.ifid2addr[path.get_first_hop_of().ingress_if]
            else:
                hop = self.ifid2addr[path.get_first_hop_of().egress_if]
            path_len = len(raw_path) // 8  # Check whether 8 divides path_len?
            reply.append(struct.pack("B", path_len) + raw_path + hop.packed)
        self._api_socket.sendto(b"".join(reply), sender)

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
            threading.Thread(target=self._api_handle_path_request,
                             args=[packet, sender]).start()
        else:
            logging.warning("API: type %d not supported.", packet[0])

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
        if from_local_socket:  # From PS or CS.
            pkt = PathMgmtPacket(packet)
            if pkt.type == PMT.RECORDS:
                self.handle_path_reply(pkt.payload)
            else:
                logging.warning("Type %d not supported.", pkt.type)
        else:  # From localhost (SCIONDaemon API)
            self.api_handle_request(packet, sender)
