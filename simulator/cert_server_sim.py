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
:mod:`cert_server_sim` --- SCION certificate server sim
===============================================
"""

import logging
from infrastructure.cert_server import CertServer
from lib.defines import SCION_UDP_PORT
from lib.packet.scion import (
    CertChainReply,
    TRCReply
)
from lib.util import (
    get_cert_chain_file_path,
    get_trc_file_path,
    write_file
)
from simulator.simulator import add_element, schedule


class CertServerSim(CertServer):
    """
    The SCION Certificate Server - Simulator
    """
    def __init__(self, server_id, topo_file, config_file, trc_file):
        """
        Initialises CertServer with is_sim set to True.
        """
        CertServer.__init__(self, server_id, topo_file, config_file,
                            trc_file, is_sim=True)
        add_element(str(self.addr.host_addr), self)

    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        schedule(0., dst=str(dst),
                 args=(packet.pack(),
                       (str(self.addr), SCION_UDP_PORT),
                       (str(dst), dst_port)))

    def sim_recv(self, packet, src, dst):
        """
        The receive function called when simulator receives a packet
        """
        to_local = False
        if dst[0] == str(self.addr.host_addr) and dst[1] == SCION_UDP_PORT:
            to_local = True
        self.handle_request(packet, src, to_local)

    def run(self):
        """
        Run function should not do anything
        """
        pass

    def clean(self):
        """
        Clean function should not do anything
        """
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


