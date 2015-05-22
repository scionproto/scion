"""
sim_app.py

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
from ipaddress import IPv4Address
from lib.packet.path import (
    CorePath,
    PeerPath,
    CrossOverPath,
    EmptyPath)
from lib.packet.opaque_field import InfoOpaqueField, OpaqueFieldType
from lib.simulator import schedule
from endhost.sim_host import SCIONSimHost, SCIOND_API_PORT

class SCIONSimApplication(object):
    """
    An application to be simulated on a host(SCIONSimHost) 
    """
    def __init__(self, host, app_port):
        self.host = host
        host.add_application(self, app_port, 
            self.run, self.sim_recv, self.handle_path_reply)
        self.addr = str(host.addr.host_addr)
        logging.info("Application: %s added on host: %s",
            str(app_port), self.addr)
        self.app_cb = None
        self.app_port = app_port
        self.start_time = 0

    def start(self, start_time):
        """
        Set start time of the application
        """
        self.start_time = start_time

    def get_paths_via_api(self, isd, ad):
        """
        Test local API.
        """
        msg = b'\x00' + struct.pack("H", isd) + struct.pack("Q", ad)
        logging.info("Sending path request to local API.")
        eid = schedule(0., dst=self.addr,
                        args=(msg,
                            (self.addr, self.app_port),
                            (self.addr, SCIOND_API_PORT)))
        assert eid >= 0

    def handle_path_reply(self, data):
        """
        Used as a callback by the host after path reply is constructed
        """ 
        offset = 0
        paths_hops = []
        while offset < len(data):
            path_len = int(data[offset]) * 8
            offset += 1
            raw_path = data[offset:offset+path_len]
            path = None
            info = InfoOpaqueField(raw_path[0:InfoOpaqueField.LEN])
            if info.info == OpaqueFieldType.TDC_XOVR:
                path = CorePath(raw_path)
            elif info.info == OpaqueFieldType.NON_TDC_XOVR:
                path = CrossOverPath(raw_path)
            elif info.info == OpaqueFieldType.INTRATD_PEER:
                path = PeerPath(raw_path)
            elif info.info == 0x00:
                path = EmptyPath()
            else:
                logging.info("Can not parse path: Unknown type %x", info.info)
            assert path
            offset += path_len
            hop = IPv4Address(data[offset:offset+4])
            offset += 4
            paths_hops.append((path, hop))
        if self.app_cb is not None:
            self.app_cb(paths_hops)

    def run(self):
        """
        This function will be run at start of simulator
        Function is to be overridden by application
        """
        pass

    def sim_recv(self, packet, src, dst):
        """
        The receive function called when simulator receives a packet
        """
        self.handle_packet(packet, src)

    def handle_packet(self, packet, sender):
        """
        Handling the incoming packets
        Function is to be overridden by application
        """
        pass
