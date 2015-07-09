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
:mod:`sim_app` --- Generic Application for Simulator
====================================================
"""
# Stdlib
import logging
import struct
from ipaddress import IPv4Address

# SCION
from lib.packet.opaque_field import (
    InfoOpaqueField,
    OpaqueFieldType as OFT,
)
from lib.packet.path import (
    CorePath,
    PeerPath,
    CrossOverPath,
    EmptyPath,
)

# SCION Simulator
from simulator.endhost.sim_host import SCIOND_API_PORT


class SCIONSimApplication(object):
    """
    An application to be simulated on a host(SCIONSimHost)
    """
    def __init__(self, host, app_port):
        """
        Initialize the application

        :param host: The host on which application is to be run
        :type host: SCIONSimHost
        :param app_port: The application port
        :type app_port: int
        """
        self.host = host
        host.add_application(self, app_port, self.run,
                             self.sim_recv, self.handle_path_reply)
        self.addr = str(host.addr.host_addr)
        logging.info("Application: %s added on host: %s",
                     str(app_port), self.addr)
        # Application callback used to call after paths are known
        self.app_cb = None
        self.app_port = app_port
        self.start_time = 0
        self.simulator = host.simulator

    def start(self, start_time):
        """
        Set start time of the application

        :param start_time: The time at which application starts
        :type start_time: float
        """
        self.start_time = start_time

    def get_paths_via_api(self, isd, ad):
        """
        Send path request to API port of the host

        :param isd: The isd number corresponding to path request
        :type isd: int
        :param ad: The ad number corresponding to path request
        :type ad: int
        """
        msg = b'\x00' + struct.pack("H", isd) + struct.pack("Q", ad)
        logging.info("Sending path request to local API.")
        eid = self.simulator.add_event(0., dst=self.addr,
                                       args=(msg,
                                             (self.addr, self.app_port),
                                             (self.addr, SCIOND_API_PORT)))
        assert eid >= 0

    def handle_path_reply(self, data):
        """
        Used as a callback by the host after path reply is constructed

        :param data: Data corresponding to path reply
        :type data: bytes
        """
        offset = 0
        paths_hops = []
        while offset < len(data):
            path_len = int(data[offset]) * 8
            offset += 1
            raw_path = data[offset:offset + path_len]
            path = None
            info = InfoOpaqueField(raw_path[0:InfoOpaqueField.LEN])
            if info.info == OFT.TDC_XOVR:
                path = CorePath(raw_path)
            elif info.info == OFT.NON_TDC_XOVR:
                path = CrossOverPath(raw_path)
            elif (info.info == OFT.INTRATD_PEER or
                  info.info == OFT.INTERTD_PEER):
                path = PeerPath(raw_path)
            elif info.info == 0x00:
                path = EmptyPath()
            else:
                logging.info("Can not parse path in packet: Unknown type %x",
                             info.info)
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
        The receive function called when a packet is received
        """
        self.handle_packet(packet, src)

    def handle_packet(self, packet, sender):
        """
        Handling the incoming packets
        Function is to be overridden by application
        """
        pass
