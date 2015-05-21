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

import collections
import logging
from infrastructure.cert_server import CertServer
from lib.defines import SCION_UDP_PORT
from ipaddress import IPv4Address
from lib.crypto.certificate import TRC
from lib.log import (init_logging, log_exception)
from lib.packet.scion import (
    CertChainReply,
    CertChainRequest,
    PacketType as PT,
    SCIONPacket,
    TRCReply,
    TRCRequest,
    get_type,
)
from lib.packet.scion_addr import SCIONAddr
from lib.simulator import add_element, schedule
from lib.util import (
    get_cert_chain_file_path,
    get_trc_file_path,
    handle_signals,
    read_file,
    timed,
    write_file,
)


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

    def process_cert_chain_reply(self, cert_chain_rep):
        """
        Process a certificate chain reply(No zookeeper).
        """
        assert isinstance(cert_chain_rep, CertChainReply)
        logging.info("Certificate chain reply received")
        cert_chain = cert_chain_rep.cert_chain
        self.cert_chains[(cert_chain_rep.isd_id, cert_chain_rep.ad_id,
                          cert_chain_rep.version)] = cert_chain
        cert_chain_file = get_cert_chain_file_path(self.topology.isd_id,
            self.topology.ad_id, cert_chain_rep.isd_id, cert_chain_rep.ad_id,
            cert_chain_rep.version)
        write_file(cert_chain_file, cert_chain.decode('utf-8'))
        # Reply to all requests for this certificate chain
        for dst_addr in self.cert_chain_requests[(cert_chain_rep.isd_id,
            cert_chain_rep.ad_id, cert_chain_rep.version)]:
            new_cert_chain_rep = CertChainReply.from_values(self.addr,
                cert_chain_rep.isd_id, cert_chain_rep.ad_id,
                cert_chain_rep.version, cert_chain_rep.cert_chain)
            self.send(new_cert_chain_rep, dst_addr)
        del self.cert_chain_requests[(cert_chain_rep.isd_id,
            cert_chain_rep.ad_id, cert_chain_rep.version)]
        logging.info("Certificate chain reply sent.")


    def process_trc_reply(self, trc_rep):
        """
        Process a TRC reply(No zookeeper).
        """
        assert isinstance(trc_rep, TRCReply)
        logging.info("TRC reply received")
        trc = trc_rep.trc
        self.trcs[(trc_rep.isd_id, trc_rep.version)] = trc
        trc_file = get_trc_file_path(self.topology.isd_id, self.topology.ad_id,
            trc_rep.isd_id, trc_rep.version)
        write_file(trc_file, trc.decode('utf-8'))
        # Reply to all requests for this TRC
        for dst_addr in self.trc_requests[(trc_rep.isd_id, trc_rep.version)]:
            new_trc_rep = TRCReply.from_values(self.addr, trc_rep.isd_id,
                trc_rep.version, trc_rep.trc)
            self.send(new_trc_rep, dst_addr)
        del self.trc_requests[(trc_rep.isd_id, trc_rep.version)]
        logging.info("TRC reply sent.")


