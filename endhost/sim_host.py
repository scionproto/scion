"""
sim_host.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import logging
import struct
from infrastructure.scion_elem import SCIONElement
from lib.defines import SCION_UDP_PORT, SCION_UDP_EH_DATA_PORT
from lib.packet.path import PathCombinator
from lib.packet.path_mgmt import (
    PathSegmentInfo,
    PathSegmentType as PST,
    PathMgmtType as PMT,
    PathMgmtPacket
)
from lib.packet.scion_addr import SCIONAddr, ISD_AD
from lib.path_db import PathSegmentDB
from lib.simulator import add_element, schedule, unschedule
from lib.util import update_dict

SCIOND_API_PORT = 3333

class SCIONSimHost(SCIONElement):
    """
    The SCION Daemon used for retrieving and combining paths.
    """

    TIMEOUT = 5

    def __init__(self, addr, topo_file):
        # Constructor of ScionElem
        self._addr = None
        self.topology = None
        self.config = None
        self.ifid2addr = {}
        self.parse_topology(topo_file)
        self.addr = SCIONAddr.from_values(self.topology.isd_id,
                                          self.topology.ad_id, addr)
        self.construct_ifid2addr_map()
        add_element(str(self.addr.host_addr), self)

        # TODO replace by pathstore instance
        self.up_segments = PathSegmentDB()
        self.down_segments = PathSegmentDB()
        self.core_segments = PathSegmentDB()
        self._waiting_targets = {PST.UP: {},
                                 PST.DOWN: {},
                                 PST.CORE: {},
                                 PST.UP_DOWN: {}}

        self.apps = {}

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

    def _expire_request_timeout(self, ptype, requestor):
        #TODO Failure Notification
        pass

    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        schedule(0., dst=str(dst),
                 args=(packet.pack(),
                       (str(self.addr), SCION_UDP_PORT),
                       (str(dst), dst_port)))

    def clean(self):
        pass

    def _request_paths(self, requestor, ptype, dst_isd, dst_ad, 
        src_core_ad=None, dst_core_ad=None):
        """
        Sends path request with certain type for (isds, ad).
        """
        src_isd = self.topology.isd_id
        src_ad = self.topology.ad_id

        eid = schedule(SCIONSimHost.TIMEOUT,
                        cb=self._expire_request_timeout,
                        args=(ptype, requestor))

        if ptype == PST.UP_DOWN or ptype == PST.UP or ptype == PST.DOWN: 
            update_dict(self._waiting_targets[ptype], 
                (dst_isd, dst_ad), [(eid, requestor, dst_ad)])
            info = PathSegmentInfo.from_values(ptype, src_isd, 
                dst_isd, src_ad, dst_ad)
        elif ptype == PST.CORE:
            update_dict(self._waiting_targets[ptype], 
                (dst_isd, dst_core_ad), [(eid, requestor, dst_ad)])
            info = PathSegmentInfo.from_values(ptype, src_isd, 
                dst_isd, src_core_ad, dst_core_ad)


        path_request = PathMgmtPacket.from_values(PMT.REQUEST,
         info, None, self.addr, ISD_AD(src_isd, src_ad))

        dst = self.topology.path_servers[0].addr
        self.send(path_request, dst)

    def get_paths(self, dst_isd, dst_ad, requestor):
        """
        Returns a list of paths.
        """
        full_paths = []
        down_segments = self.down_segments(dst_isd=dst_isd, dst_ad=dst_ad)
        # Fetch down-paths if necessary.
        if not down_segments:
            self._request_paths(requestor, PST.UP_DOWN, dst_isd, dst_ad)
            return None

        if len(self.up_segments) and down_segments:
            full_paths = PathCombinator.build_shortcut_paths(self.up_segments(),
                                                             down_segments)
            if not full_paths:
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
                    self._request_paths(requestor, PST.CORE,
                     dst_isd, dst_ad, src_core_ad, dst_core_ad)
                    return None

                full_paths = PathCombinator.build_core_paths(
                    self.up_segments()[0],
                    down_segments[0],
                    core_segments)

        return full_paths

    def _get_full_paths(self, src_isd, src_ad, dst_isd, dst_ad, 
        src_core_ad=None, dst_core_ad=None):
        """
        Combines up-paths, core-paths and down-paths to get a full path
        """
        full_paths=[]
        if src_core_ad is None and dst_core_ad is None:
            down_segments = self.down_segments(dst_isd=dst_isd, dst_ad=dst_ad)
            if len(self.up_segments) and down_segments:
                full_paths = PathCombinator.build_shortcut_paths(
                    self.up_segments(), down_segments)
            if full_paths:
                return full_paths
        
        if src_core_ad is None or dst_core_ad is None:
            return None

        core_segments = self.core_segments(src_isd=src_isd, 
            src_ad=src_core_ad, dst_isd=dst_isd, dst_ad=dst_core_ad)
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
                full_paths = PathCombinator.build_core_paths(up_segment, 
                    down_segment, core_segments)

        return full_paths

    def handle_path_reply(self, path_reply):
        """
        Handles path reply from local path server.
        """
        logging.debug("handle_path_reply")
        info = path_reply.info

        if info.type == PST.DOWN:
            logging.debug("PST.DOWN")
        elif info.type == PST.UP:
            logging.debug("PST.UP")
        elif info.type == PST.UP_DOWN:
            logging.debug("PST.UP_DOWN")
        elif info.type == PST.CORE:
            logging.debug("PST.CORE")

        for pcb in path_reply.pcbs:
            isd = pcb.get_isd()
            ad = pcb.get_last_pcbm().ad_id

            if ((self.topology.isd_id != isd or self.topology.ad_id != ad)
                and info.type in [PST.DOWN, PST.UP_DOWN]
                and info.dst_isd == isd and info.dst_ad == ad):
                self.down_segments.update(pcb, info.src_isd, info.src_ad,
                                          info.dst_isd, info.dst_ad)
                logging.info("DOWN PATH added for (%d,%d)", isd, ad)
            elif ((self.topology.isd_id == isd and self.topology.ad_id == ad)
                and info.type in [PST.UP, PST.UP_DOWN]):
                self.up_segments.update(pcb, isd, ad, pcb.get_isd(),
                                        pcb.get_first_pcbm().ad_id)
                logging.info("UP PATH added for (%d, %d)", isd, ad)
            elif info.type == PST.CORE:
                self.core_segments.update(pcb, info.src_isd, info.src_ad,
                                          info.dst_isd, info.dst_ad)
                logging.info("CORE PATH added for (%d, %d)",
                    info.dst_isd, info.dst_ad)
            else:
                logging.warning("Incorrect path in Path Record")

        if (info.dst_isd, info.dst_ad) in self._waiting_targets[info.type]:
            for (eid, requestor, dst_ad) in \
                self._waiting_targets[info.type][(info.dst_isd, info.dst_ad)]:

                src_isd = self.topology.isd_id
                src_ad = self.topology.ad_id
                dst_isd = info.dst_isd
                
                if info.type == PST.UP_DOWN:
                    full_paths = self._get_full_paths(src_isd, src_ad, 
                        dst_isd, dst_ad)
                    down_segments = self.down_segments(dst_isd=dst_isd, 
                        dst_ad=dst_ad)
                    if len(self.up_segments) and down_segments:
                        unschedule(eid)
                        self._waiting_targets[info.type][(dst_isd, dst_ad)].remove(
                            (eid, requestor, dst_ad))
                    else:
                        continue

                    if not full_paths:
                        src_core_ad = self.up_segments()[0].get_first_pcbm().ad_id
                        dst_core_ad = down_segments[0].get_first_pcbm().ad_id
                        self._request_paths(requestor, PST.CORE, dst_isd, 
                            dst_ad, src_core_ad, dst_core_ad)
                        continue
                elif info.type == PST.CORE:
                    src_core_ad = info.src_ad
                    dst_core_ad = info.dst_ad
                    full_paths = self._get_full_paths(src_isd, src_ad, 
                        dst_isd, dst_ad, src_core_ad, dst_core_ad)
                    if self.core_segments(src_isd=src_isd, 
                        src_ad=src_core_ad, dst_isd=dst_isd, dst_ad=dst_core_ad):
                        unschedule(eid)
                        self._waiting_targets[info.type][(dst_isd, dst_core_ad)].remove(
                            (eid, requestor, dst_ad))
                    else:
                        continue

                    if not full_paths:
                        #TODO What action to be taken?
                        continue
                elif info.type == PST.UP and len(self.up_segments):
                    full_paths = self._get_full_paths(src_isd, src_ad, 
                        dst_isd, dst_ad)
                    unschedule(eid)
                    self._waiting_targets[info.type][(dst_isd, dst_ad)].remove(
                        (eid, requestor, dst_ad))
                    if not full_paths:
                        #TODO What action to be taken?
                        continue
                elif info.type == PST.DOWN and self.down_segments(dst_isd=dst_isd, 
                    dst_ad=dst_ad):
                    full_paths = self._get_full_paths(src_isd, src_ad, 
                        dst_isd, dst_ad)
                    unschedule(eid)
                    self._waiting_targets[info.type][(dst_isd, dst_ad)].remove(
                        (eid, requestor, dst_ad))
                    if not full_paths:
                        #TODO What action to be taken?
                        continue

                self._api_send_path_reply(full_paths, requestor)

            if info.type in [PST.UP_DOWN, PST.UP, PST.DOWN]:
                if len(self._waiting_targets[info.type][(info.dst_isd, info.dst_ad)]) == 0:
                    del self._waiting_targets[info.type][(info.dst_isd, info.dst_ad)]
            elif info.type in [PST.CORE]:
                if len(self._waiting_targets[info.type][(info.dst_isd, info.dst_ad)]) == 0:
                    del self._waiting_targets[info.type][(info.dst_isd, info.dst_ad)]

    def _api_send_path_reply(self, paths, requestor):
        """
        Send path reply to the requestor
        """
        reply = []
        for path in paths:
            raw_path = path.pack()
            # assumed: up-path nad IPv4 addr
            hop = self.ifid2addr[path.get_first_hop_of().ingress_if]
            
            path_len = len(raw_path) // 8  # Check whether 8 divides path_len?
            reply.append(struct.pack("B", path_len) + raw_path + hop.packed)

        _, _, _, path_cb = self.apps[requestor[1]]
        path_cb(b"".join(reply))

    def _api_handle_path_request(self, packet, sender):
        """
        Path request:
          | \x00 (1B) | ISD (2B) |  AD (8B)  |
        Reply:
          |path1_len(1B)|path1(path1_len*8B)|first_hop_IP(4B)|path2_len(1B)...
         or b"" when no path found. Only IPv4 supported currently.
        """
        # TODO sanity checks
        isd = struct.unpack("H", packet[1:3])[0]
        ad = struct.unpack("Q", packet[3:])[0]

        logging.info("Request for %d, %d", isd, ad)

        full_paths = self.get_paths(isd, ad, sender)
        if full_paths:
            # CHANGED
            self._api_send_path_reply (self, full_paths, sender)
            return

    def api_handle_request(self, packet, sender):
        """
        Handles local API's requests.
        """
        if packet[0] == 0:  # path request
            logging.info('API: path request from %s.', sender)
            self._api_handle_path_request(packet, sender)
        else:
            logging.warning("API: type %d not supported.", packet[0])

    def handle_request(self, packet, sender, from_local_socket=True):
        # PSz: local_socket may be misleading, especially that we have api_socket
        # which is local (in the localhost sense). What do you think about
        # changing local_socket to ad_socket
        """
        Main routine to handle incoming SCION packets.
        """
        if from_local_socket:  # From PS or CS.
            pkt = PathMgmtPacket(packet)
            if pkt.type == PMT.RECORDS:
                self.handle_path_reply(pkt.payload)
            else:
                logging.warning("Type %d not supported.", pkt.type)
        else:  # From localhost (SCIONSimHost API)
            self.api_handle_request(packet, sender)

    def sim_recv(self, packet, src, dst):
        """
        The receive function called when simulator receives a packet
        """
        if dst[1] == SCION_UDP_EH_DATA_PORT:
            assert dst[0] == str(self.addr.host_addr)
            #TODO For now, a hack!!
            _,_,recv_cb,_=list(self.apps.values())[0]
            recv_cb(packet, src, dst)
        #if dst[0] == str(self.addr) and dst[1] in self.apps:
        #    _,_,recv_cb,_=self.apps[dst[1]]
        #    recv_cb(packet, src, dst)
        else:
            to_local = False
            if dst[0] == str(self.addr.host_addr) and dst[1] == SCION_UDP_PORT:
                to_local = True
            self.handle_request(packet, src, to_local)

