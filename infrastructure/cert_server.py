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

from lib.packet.host_addr import IPv4HostAddr
from lib.packet.scion import (SCIONPacket, get_type, PacketType as PT,
    CertRequest, CertReply, TRCRequest, TRCReply)
from infrastructure.scion_elem import SCIONElement
from lib.util import (read_file, write_file, get_cert_file_path,
    get_trc_file_path, init_logging)
import sys
import logging
import datetime
import os


class CertServer(SCIONElement):
    """
    The SCION Certificate Server.
    """
    def __init__(self, addr, topo_file, config_file, trc_file):
        SCIONElement.__init__(self, addr, topo_file, config_file, trc_file)
        self.cert_requests = {}
        self.trc_requests = {}

    def process_cert_request(self, cert_req):
        """
        Process a certificate request.
        """
        assert isinstance(cert_req, CertRequest)
        logging.info("Cert request received")
        src_addr = cert_req.hdr.src_addr
        ptype = get_type(cert_req)
        cert_file = get_cert_file_path(self.topology.isd_id,
            self.topology.ad_id, cert_req.cert_isd, cert_req.cert_ad,
            cert_req.cert_version)
        if not os.path.exists(cert_file):
            logging.info('Certificate not found.')
            self.cert_requests.setdefault((cert_req.cert_isd, cert_req.cert_ad,
                cert_req.cert_version), []).append(src_addr)
            new_cert_req = CertRequest.from_values(PT.CERT_REQ, self.addr,
                cert_req.ingress_if, cert_req.src_isd, cert_req.src_ad,
                cert_req.cert_isd, cert_req.cert_ad, cert_req.cert_version)
            dst_addr = self.ifid2addr[cert_req.ingress_if]
            self.send(new_cert_req, dst_addr)
            logging.info("New certificate request sent.")
        else:
            logging.info('Certificate file found.')
            cert = read_file(cert_file).encode('utf-8')
            cert_rep = CertReply.from_values(self.addr, cert_req.cert_isd,
                cert_req.cert_ad, cert_req.cert_version, cert)
            if ptype == PT.CERT_REQ_LOCAL:
                dst_addr = src_addr
            else:
                for router in self.topology.child_edge_routers:
                    if (cert_req.src_isd == router.interface.neighbor_isd and
                        cert_req.src_ad == router.interface.neighbor_ad):
                        dst_addr = router.addr
            self.send(cert_rep, dst_addr)
            logging.info("Certificate reply sent.")

    def process_cert_reply(self, cert_rep):
        """
        Process a certificate reply.
        """
        assert isinstance(cert_rep, CertReply)
        logging.info("Certificate reply received")
        cert_file = get_cert_file_path(self.topology.isd_id,
            self.topology.ad_id, cert_rep.cert_isd, cert_rep.cert_ad,
            cert_rep.cert_version)
        write_file(cert_file, cert_rep.cert.decode('utf-8'))
        for dst_addr in self.cert_requests[(cert_rep.cert_isd, cert_rep.cert_ad,
            cert_rep.cert_version)]:
            new_cert_rep = CertReply.from_values(self.addr, cert_rep.cert_isd,
                cert_rep.cert_ad, cert_rep.cert_version, cert_rep.cert)
            self.send(new_cert_rep, dst_addr)
        del self.cert_requests[(cert_rep.cert_isd, cert_rep.cert_ad,
            cert_rep.cert_version)]
        logging.info("Certificate reply sent.")

    def process_trc_request(self, trc_req):
        """
        Process a TRC request.
        """
        assert isinstance(trc_req, TRCRequest)
        logging.info("TRC request received")
        src_addr = trc_req.hdr.src_addr
        ptype = get_type(trc_req)
        trc_file = get_trc_file_path(self.topology.isd_id, self.topology.ad_id,
            trc_req.trc_isd, trc_req.trc_version)
        if not os.path.exists(trc_file):
            logging.info('TRC file not found.')
            self.trc_requests.setdefault((trc_req.trc_isd, trc_req.trc_version),
                []).append(src_addr)
            new_trc_req = TRCRequest.from_values(PT.TRC_REQ, self.addr,
                trc_req.ingress_if, trc_req.src_isd, trc_req.src_ad,
                trc_req.trc_isd, trc_req.trc_version)
            dst_addr = self.ifid2addr[trc_req.ingress_if]
            self.send(new_trc_req, dst_addr)
            logging.info("New TRC request sent.")
        else:
            logging.info('TRC file found.')
            trc = read_file(trc_file).encode('utf-8')
            trc_rep = TRCReply.from_values(self.addr, trc_req.trc_isd,
                trc_req.trc_version, trc)
            if ptype == PT.TRC_REQ_LOCAL:
                dst_addr = src_addr
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
        trc_file = get_trc_file_path(self.topology.isd_id, self.topology.ad_id,
            trc_rep.trc_isd, trc_rep.trc_version)
        write_file(trc_file, trc_rep.trc.decode('utf-8'))
        for dst_addr in self.trc_requests[(trc_rep.trc_isd,
            trc_rep.trc_version)]:
            new_trc_rep = TRCReply.from_values(self.addr, trc_rep.trc_isd,
                trc_rep.trc_version, trc_rep.trc)
            self.send(new_trc_rep, dst_addr)
        del self.trc_requests[(trc_rep.trc_isd, trc_rep.trc_version)]
        logging.info("TRC reply sent.")

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        if ptype == PT.CERT_REQ_LOCAL or ptype == PT.CERT_REQ:
            self.process_cert_request(CertRequest(packet))
        elif ptype == PT.CERT_REP:
            self.process_cert_reply(CertReply(packet))
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

    cert_server = CertServer(IPv4HostAddr(sys.argv[1]), sys.argv[2],
        sys.argv[3], sys.argv[4])

    logging.info("Started: %s", datetime.datetime.now())
    cert_server.run()

if __name__ == "__main__":
    main()
