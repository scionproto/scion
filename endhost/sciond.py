"""
sciond.py

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

from infrastructure.scion_elem import SCIONElement
from lib.packet.host_addr import IPv4HostAddr
from lib.packet.path import PathCombinator
from lib.packet.scion import (SCIONPacket, get_type, PathRequest, PathRecords,
    PathInfo, PathInfoType as PIT)
from lib.packet.scion import PacketType as PT
from lib.topology import ElementType
from lib.util import update_dict
import logging
import sys
import threading


PATHS_NO = 5  # conf parameter?
WAIT_CYCLES = 3

class SCIONDaemon(SCIONElement):
    """
    The SCION Daemon used for retrieving and combining paths.
    """

    TIMEOUT = 7

    def __init__(self, addr, topo_file):
        SCIONElement.__init__(self, addr, topo_file)
        # TODO replace by pathstore instance
        self.up_paths = []
        self.down_paths = {}
        self.core_paths = {}
        self._waiting_targets = {PIT.UP: {},
                                 PIT.DOWN: {},
                                 PIT.CORE: {},
                                 PIT.ALL: {}}

    @classmethod
    def start(cls, addr, topo_file):
        """
        Initializes, starts, and returns a SCIONDaemon object.

        Example of usage:
        sd = SCIONDaemon.start(addr, topo_file)
        paths = sd.get_paths(isd_id, ad_id)
        ...
        """
        sd = cls(addr, topo_file)
        threading.Thread(target=sd.run).start()
        return sd

    def _request_paths(self, type, dst_isd, dst_ad, src_isd=None, src_ad=None):
        """
        Sends path request with certain type for (isd, ad).
        """
        if src_isd is None:
            src_isd = self.topology.isd_id
        if src_ad is None:
            src_ad = self.topology.ad_id

        # Create an event that we can wait on for the path reply.
        event = threading.Event()
        update_dict(self._waiting_targets[type], (dst_isd, dst_ad), [event])

        # Create and send out path request.
        info = PathInfo.from_values(type, src_isd, dst_isd, src_ad, dst_ad)
        path_request = PathRequest.from_values(self.addr, info)
        dst = self.topology.servers[ElementType.PATH_SERVER].addr
        self.send(path_request, dst)

        # Wait for path reply and clear us from the waiting list when we got it.
        cycle_cnt = 0
        while cycle_cnt < WAIT_CYCLES:
            event.wait(SCIONDaemon.TIMEOUT)
            # Check that we got all the requested paths.
            if ((type == PIT.UP and self.up_paths) or
                (type == PIT.DOWN, PIT.ALL and
                (dst_isd, dst_ad) in self.down_paths) or
                (type == PIT.CORE and ((src_isd, src_ad), (dst_isd, dst_ad)) in
                 self.core_paths) or
                (type == PIT.ALL and (self.up_paths and (dst_isd, dst_ad) in
                self.down_paths))):
                self._waiting_targets[type][(dst_isd, dst_ad)].remove(event)
                if self._waiting_targets[type][(dst_isd, dst_ad)]:
                    del self._waiting_targets[type][(dst_isd, dst_ad)]
                break
            cycle_cnt += 1


    def get_paths(self, dst_isd, dst_ad):
        """
        Returns a list of paths.
        """
        paths = []
        # Fetch down-paths if necessary.
        if (dst_isd, dst_ad) not in self.down_paths:
            self._request_paths(PIT.ALL, dst_isd, dst_ad)

        if self.up_paths and (dst_isd, dst_ad) in self.down_paths:
            paths = PathCombinator.build_shortcut_paths(self.up_paths,
                self.down_paths[(dst_isd, dst_ad)])
            if paths:
                return paths
            else:
                # No shortcut path could be built. Select an up and down path
                # and request a set of core-paths connecting them.
                # For now we just choose the first up-/down-path.
                # TODO: Atm an application can't choose the up-/down-path to be
                #       be used. Discuss with Pawel.
                src_isd = self.topology.isd_id
                src_core_ad = self.up_paths[0].ads[0]
                dst_core_ad = self.down_paths[0].ads[0]
                core_paths = []
                if ((src_isd, src_core_ad) != (dst_isd, dst_core_ad)):
                    if (((src_isd, src_core_ad), (dst_isd, dst_core_ad)) not in
                        self.core_paths):
                        self._request_paths(PIT.CORE, dst_isd, dst_core_ad,
                                            src_ad=src_core_ad)
                    core_paths = self.core_paths[((src_isd, src_core_ad),
                                                  (dst_isd, dst_core_ad))]

                paths = PathCombinator.build_core_paths(self.up_paths[0],
                                                        self.down_paths[0],
                                                        core_paths)

        return paths

    def handle_path_reply(self, packet):
        """
        Handles path reply from local path server.
        """
        path_reply = PathRecords(packet)
        info = path_reply.info
        new_down_paths = []
        new_core_paths = []
        for pcb in path_reply.pcbs:
            isd = pcb.get_isd()
            ad = pcb.get_last_ad_id()

            if ((self.topology.isd_id != isd or self.topology.ad_id != ad)
                and info.type in [PIT.DOWN, PIT.ALL]
                and info.dst_isd == isd and info.dst_ad == ad):
                new_down_paths.append(pcb)
                logging.info("DownPath PATH added for (%d,%d)", isd, ad)
            elif ((self.topology.isd_id == isd and self.topology.ad_id == ad)
                and info.type in [PIT.UP, PIT.ALL]):
                self.up_paths.append(pcb)
                logging.info("UP PATH added")
            elif info.type == PIT.CORE:
                new_core_paths.append(pcb)
            else:
                logging.warning("Incorrect path in Path Record")
                print(isd, ad, info.__dict__)
        update_dict(self.down_paths, (info.dst_isd, info.dst_ad),
                    new_down_paths, PATHS_NO)
        update_dict(self.core_paths,
                    ((info.src_isd, info.src_ad), (info.dst_isd, info.dst_ad)),
                    new_core_paths,
                    PATHS_NO)

        # Wake up sleeping get_paths().
        if (isd, ad) in self._waiting_targets[info.type]:
            for event in \
                self._waiting_targets[info.type][(info.dst_isd, info.dst_ad)]:
                event.set()

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)

        if ptype == PT.PATH_REC:
            self.handle_path_reply(packet)
        else:
            logging.warning("Type %d not supported.", ptype)

