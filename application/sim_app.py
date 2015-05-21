"""
end2end_test.py

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
from ipaddress import IPv4Address
from lib.packet.path import (CorePath, PeerPath, CrossOverPath,
                             EmptyPath, PathBase)
from lib.packet.opaque_field import InfoOpaqueField, OpaqueFieldType
from lib.packet.scion import SCIONPacket
from lib.simulator import schedule, add_element
from endhost.sim_host import SCIONSimHost, SCIOND_API_PORT
import logging
import sys
import struct

class SCIONSimApplication(object):
    def __init__(self, host, app_port):
        self.host = host
        host.add_application(self, app_port, self.run, self.sim_recv, self.handle_path_reply)
        self.addr = str(host.addr.host_addr);
        logging.info("Application: %s added on host: %s", str(app_port), self.addr)
        self.app_cb = None
        self.app_port = app_port
        self.start_time = 0
 
    def start(self, start_time):
        self.start_time = start_time

    def get_paths_via_api(self, isd, ad):
        """
        Test local API.
        """
        msg = b'\x00' + struct.pack("H", isd) + struct.pack("Q", ad)
        logging.info("Sending path request to local API.")
        eid = schedule (0., dst=self.addr,
                        args=(msg,
                            (self.addr, self.app_port),
                            (self.addr, SCIOND_API_PORT)))
        assert (eid >= 0)

    #Used as a callback by 
    def handle_path_reply(self, data):
        logging.info('sim_app: handle_path_reply')
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
            self.app_cb (paths_hops)

    # run() is intentionally designed to be identical to
    # the run() defined for SCIONElement  
    def run(self):
        pass

    # sim_recv() is intentionally designed to be identical to 
    # the sim_recv() defined for SCIONElement
    def sim_recv (self, packet, src, dst):
        self.handle_packet (packet, src)

    # Function name and args made the same to the SCIONElement
    def handle_packet(self, packet, sender):
        pass
