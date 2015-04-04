# Copyright 2014 ETH Zurich

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`cert_server` --- SCION certificate server
===========================================
"""

from infrastructure.scion_elem import SCIONElement
from ipaddress import IPv4Address
from lib.crypto.certificate import TRC
from lib.packet.scion import (SCIONPacket, get_type, PacketType as PT,
    CertChainRequest, CertChainReply, TRCRequest, TRCReply)
from lib.util import (read_file, write_file, get_cert_chain_file_path,
    get_trc_file_path, init_logging)
import collections
import datetime
import logging
import os
import sys


class CertServer(SCIONElement):
    """
    The SCION Certificate Server.
    """
    def __init__(self, addr, topo_file, config_file, trc_file):
        SCIONElement.__init__(self, addr, topo_file, config_file=config_file)
        self.trc = TRC(trc_file)
        self.cert_chain_requests = collections.defaultdict(list)
        self.trc_requests = collections.defaultdict(list)
        self.cert_chains = {}
        self.trcs = {}

    def process_cert_chain_request(self, cert_chain_req):
        """
        Process a certificate chain request.
        """
        assert isinstance(cert_chain_req, CertChainRequest)
        logging.info("Certificate chain request received.")
        cert_chain = self.cert_chains.get((cert_chain_req.isd_id,
            cert_chain_req.ad_id, cert_chain_req.version))
        if not cert_chain:
            # Try loading file from disk
            cert_chain_file = get_cert_chain_file_path(self.topology.isd_id,
                self.topology.ad_id, cert_chain_req.isd_id,
                cert_chain_req.ad_id, cert_chain_req.version)
            if os.path.exists(cert_chain_file):
                cert_chain = read_file(cert_chain_file).encode('utf-8')
                self.cert_chains[(cert_chain_req.isd_id, cert_chain_req.ad_id,
                                  cert_chain_req.version)] = cert_chain
        if not cert_chain:
            # Requesting certificate chain file from parent's cert server
            logging.debug('Certificate chain not found.')
            cert_chain_tuple = (cert_chain_req.isd_id, cert_chain_req.ad_id,
                                cert_chain_req.version)
            self.cert_chain_requests[cert_chain_tuple].append(
                cert_chain_req.hdr.src_addr.host_addr)
            new_cert_chain_req = CertChainRequest.from_values(PT.CERT_CHAIN_REQ,
                self.addr, cert_chain_req.ingress_if, cert_chain_req.src_isd,
                cert_chain_req.src_ad, cert_chain_req.isd_id,
                cert_chain_req.ad_id, cert_chain_req.version)
            dst_addr = self.ifid2addr[cert_chain_req.ingress_if]
            self.send(new_cert_chain_req, dst_addr)
            logging.info("New certificate chain request sent.")
        else:
            logging.debug('Certificate chain found.')
            cert_chain_rep = CertChainReply.from_values(self.addr,
                cert_chain_req.isd_id, cert_chain_req.ad_id,
                cert_chain_req.version, cert_chain)
            if get_type(cert_chain_req) == PT.CERT_CHAIN_REQ_LOCAL:
                dst_addr = cert_chain_req.hdr.src_addr.host_addr
            else:
                for router in self.topology.child_edge_routers:
                    if (cert_chain_req.src_isd == router.interface.neighbor_isd
                        and
                        cert_chain_req.src_ad == router.interface.neighbor_ad):
                        dst_addr = router.addr
            self.send(cert_chain_rep, dst_addr)
            logging.info("Certificate chain reply sent.")

    def process_cert_chain_reply(self, cert_chain_rep):
        """
        Process a certificate chain reply.
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

    def process_trc_request(self, trc_req):
        """
        Process a TRC request.
        """
        assert isinstance(trc_req, TRCRequest)
        logging.info("TRC request received")
        trc = self.trcs.get((trc_req.isd_id, trc_req.version))
        if not trc:
            # Try loading file from disk
            trc_file = get_trc_file_path(self.topology.isd_id,
                self.topology.ad_id, trc_req.isd_id, trc_req.version)
            if os.path.exists(trc_file):
                trc = read_file(trc_file).encode('utf-8')
                self.trcs[(trc_req.isd_id, trc_req.version)] = trc
        if not trc:
            # Requesting TRC file from parent's cert server
            logging.debug('TRC not found.')
            trc_tuple = (trc_req.isd_id, trc_req.version)
            self.trc_requests[trc_tuple].append(trc_req.hdr.src_addr.host_addr)
            new_trc_req = TRCRequest.from_values(PT.TRC_REQ, self.addr,
                trc_req.ingress_if, trc_req.src_isd, trc_req.src_ad,
                trc_req.isd_id, trc_req.version)
            dst_addr = self.ifid2addr[trc_req.ingress_if]
            self.send(new_trc_req, dst_addr)
            logging.info("New TRC request sent.")
        else:
            logging.debug('TRC found.')
            trc_rep = TRCReply.from_values(self.addr, trc_req.isd_id,
                trc_req.version, trc)
            if get_type(trc_req) == PT.TRC_REQ_LOCAL:
                dst_addr = trc_req.hdr.src_addr.host_addr
            else:
                for router in self.topology.child_edge_routers:
                    if (trc_req.src_isd == router.interface.neighbor_isd and
                        trc_req.src_ad == router.interface.neighbor_ad):
                        dst_addr = router.addr
            self.send(trc_rep, dst_addr)
            logging.info("TRC reply sent.")

    def process_trc_reply(self, trc_rep):
        """
        Process a TRC reply.
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

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        if ptype == PT.CERT_CHAIN_REQ_LOCAL or ptype == PT.CERT_CHAIN_REQ:
            self.process_cert_chain_request(CertChainRequest(packet))
        elif ptype == PT.CERT_CHAIN_REP:
            self.process_cert_chain_reply(CertChainReply(packet))
        elif ptype == PT.TRC_REQ_LOCAL or ptype == PT.TRC_REQ:
            self.process_trc_request(TRCRequest(packet))
        elif ptype == PT.TRC_REP:
            self.process_trc_reply(TRCReply(packet))
        else:
            logging.info("Type not supported")

def main():
    """
    Main function.
    """
    init_logging()
    if len(sys.argv) != 5:
        logging.error("run: %s IP topo_file conf_file trc_file", sys.argv[0])
        sys.exit()

    cert_server = CertServer(IPv4Address(sys.argv[1]), sys.argv[2],
                             sys.argv[3], sys.argv[4])

    logging.info("Started: %s", datetime.datetime.now())
    cert_server.run()

if __name__ == "__main__":
    main()
