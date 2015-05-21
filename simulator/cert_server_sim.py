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
:mod:`cert_server_sim` --- SCION certificate server sim
===============================================
"""

from infrastructure.scion_elem import SCIONElement
from ipaddress import IPv4Address
from lib.crypto.certificate import TRC
from lib.packet.scion import (SCIONPacket, get_type, PacketType as PT,
    CertChainRequest, CertChainReply, TRCRequest, TRCReply)
from lib.util import (read_file, write_file, get_cert_chain_file_path,
    get_trc_file_path, handle_signals)
from lib.log import (init_logging, log_exception)
import collections
import datetime
import logging
import os
import sys
from infrastructure.scion_elem import SCION_UDP_PORT
from lib.packet.scion_addr import SCIONAddr
from lib.simulator import add_element, schedule
from infrastructure.cert_server import CertServer


class CertServerSim(CertServer):
    """
    The SCION Certificate Server - Simulator
    """
    def __init__(self, addr, topo_file, config_file, trc_file):
        # Constructor of ScionElem
        self._addr = None
        self.topology = None
        self.config = None
        self.ifid2addr = {}
        self.parse_topology(topo_file)
        self.addr = SCIONAddr.from_values(self.topology.isd_id,
                                          self.topology.ad_id, addr)
        if config_file:
            self.parse_config(config_file)
        self.construct_ifid2addr_map()
        add_element(str(self.addr.host_addr), self)

        #Constructor of CS
        self.trc = TRC(trc_file)
        self.cert_chain_requests = collections.defaultdict(list)
        self.trc_requests = collections.defaultdict(list)
        self.cert_chains = {}
        self.trcs = {}

    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        schedule(0., dst=str(dst),
                 args=(packet.pack(),
                       (str(self.addr), SCION_UDP_PORT),
                       (str(dst), dst_port)))

    def sim_recv(self, packet, src, dst):
        to_local = False
        if dst[0] == str(self.addr.host_addr) and dst[1] == SCION_UDP_PORT:
            to_local = True
        self.handle_request(packet, src, to_local)

    def run(self):
        pass

    def clean(self):
        pass
