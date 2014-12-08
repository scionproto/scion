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

from lib.packet.host_addr import IPv4HostAddr
from lib.packet.path import PathCombinator
from lib.packet.scion import (SCIONPacket, get_type, PathRequest, PathRecords,
    PathInfo, PathInfoType as PIT)
from lib.packet.scion import PacketType as PT
from lib.topology import ElementType
from lib.util import update_dict
from infrastructure.server import ServerBase
import threading
import logging

PATHS_NO = 5 #conf parameter?

class SCIONDaemon(ServerBase):
    """
    The SCION Daemon used for retrieving and combining paths.
    """

    TIMEOUT = 7

    def __init__(self, addr, topo_file):
        ServerBase.__init__(self, addr, topo_file)
        #TODO replace by pathstore instance
        self.up_paths = []
        self.down_paths = {}
        self._waiting_targets = {}

    def request_paths(self, type, isd, ad):
        """
        Sends path request with certain type for (isd,ad).
        """
        info = PathInfo.from_values(type, isd, ad)
        path_request = PathRequest.from_values(self.addr, info)
        dst = self.topology.servers[ElementType.PATH_SERVER].addr
        self.send(path_request, dst)

    def get_paths(self, isd, ad):
        """
        Returns list of paths.
        """
        if self.up_paths and (isd, ad) in self.down_paths:
            return PathCombinator.build_fullpaths(self.up_paths,
                self.down_paths[(isd, ad)])
        else:
            #TODO add semaphore or something
            event = threading.Event()
            update_dict(self._waiting_targets, (isd, ad), [event])
            self.request_paths(PIT.BOTH, isd, ad)
            event.wait(SCIONDaemon.TIMEOUT)
            self._waiting_targets[(isd, ad)].remove(event)
            if not self._waiting_targets[(isd, ad)]:
                del self._waiting_targets[(isd, ad)]

            if self.up_paths and (isd, ad) in self.down_paths:
                return PathCombinator.build_fullpaths(self.up_paths,
                    self.down_paths[(isd, ad)])
            else:
                return []

    def handle_path_reply(self, packet):
        """
        Handles path reply from local path server.
        """
        path_reply = PathRecords(packet)
        info = path_reply.info
        new_down_paths = []
        for pcb in path_reply.pcbs:
            isd = pcb.get_isd()
            ad = pcb.get_last_ad()

            if ((self.topology.isd_id != isd or self.topology.ad_id != ad)
                and info.type in [PIT.DOWN, PIT.BOTH]
                and info.isd == isd and info.ad == ad):
                new_down_paths.append(pcb)
                logging.info("DownPath PATH added for (%d,%d)", isd, ad)
            elif ((self.topology.isd_id == isd and self.topology.ad_id == ad)
                and info.type in [PIT.UP, PIT.BOTH]):
                self.up_paths.append(pcb)
                logging.info("UP PATH added")
            else:
                logging.warning("Incorrect path in Path Record")
                print(isd,ad,info.__dict__)
        update_dict(self.down_paths, (info.isd, info.ad), new_down_paths,
            PATHS_NO)

        #Wake up sleeping get_paths().
        if (isd, ad) in self._waiting_targets:
            for event in self._waiting_targets[(isd, ad)]:
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

