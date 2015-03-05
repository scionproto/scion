"""
cert_server.py

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
from lib.packet.scion import (SCIONPacket, get_type, PacketType as PT,
    CertRequest, CertReply, RotRequest, RotReply, get_addr_from_type)
from lib.util import init_logging
from infrastructure.scion_elem import SCIONElement
from lib.packet.path import EmptyPath
import sys
import logging
import datetime
import os


ISD_PATH = '../topology/ISD'
CERTS_PATH = '/certificates/'


class CertServer(SCIONElement):
    """
    The SCION Certificate Server.
    """
    def __init__(self, addr, topo_file, config_file, rot_file):
        SCIONElement.__init__(self, addr, topo_file, config_file, rot_file)
        self.cert_requests = {}
        self.rot_requests = {}

    def _verify_cert(self, cert):
        """
        Verifies certificate validity.
        """
        return True

    def process_cert_request(self, cert_req):
        """
        Process a certificate request
        """
        isinstance(cert_req, CertRequest)
        logging.info("Cert request received")
        src_addr = cert_req.hdr.src_addr
        path = cert_req.path
        if path is None:
            # TODO: ask PS
            # if still None: return
            pass
        cert_isd = cert_req.cert_isd
        cert_ad = cert_req.cert_ad
        cert_version = cert_req.cert_version
        cert_file = (ISD_PATH + cert_isd + CERTS_PATH + 'ISD:' + cert_isd +
            '-AD:' + cert_ad + '-V:' + cert_version + '.crt')
        if not os.path.exists(cert_file):
            logging.info('Certificate %s:%s not found, sending up stream.',
                cert_isd, cert_ad)
            self.cert_requests.setdefault((cert_isd, cert_ad, cert_version),
                []).append(src_addr)
            dst_addr = get_addr_from_type(PT.CERT_REQ)
            new_cert_req = CertRequest.from_values(PT.CERT_REQ, self.addr,
                dst_addr, path, cert_isd, cert_ad, cert_version)
            self.send(new_cert_req, dst_addr)
        else:
            logging.info('Certificate %s:%s found, sending it back to ' +
                'requester(%s)', cert_isd, cert_ad, src_addr)
            with open(cert_file, 'r') as file_handler:
                cert = file_handler.read()
            if cert_req.hdr.path is None or cert_req.hdr.path == b'':
                cert_rep = CertReply.from_values(self.addr, src_addr, None,
                    cert_isd, cert_ad, cert_version, cert)
                self.send(cert_rep, src_addr)
            else:
                path = path.reverse()
                cert_rep = CertReply.from_values(self.addr, src_addr, path,
                    cert_isd, cert_ad, cert_version, cert)
                #cert_rep.hdr.set_downpath()
                (next_hop, port) = self.get_first_hop(cert_rep)
                logging.info("Sending cert reply, using path: %s", path)
                self.send(cert_rep, next_hop, port)

    def process_cert_reply(self, cert_rep):
        """
        process a certificate reply
        """
        isinstance(cert_rep, CertReply)
        logging.info("Cert reply received")
        cert_isd = cert_rep.cert_isd
        cert_ad = cert_rep.cert_ad
        cert_version = cert_rep.cert_version
        cert = cert_rep.cert
        if not self._verify_cert(cert):
            logging.info("Certificate verification failed.")
            return
        cert_file = (ISD_PATH + cert_isd + CERTS_PATH + 'ISD:' + cert_isd +
            '-AD:' + cert_ad + '-V:' + cert_version + '.crt')
        if not os.path.exists(os.path.dirname(cert_file)):
            os.makedirs(os.path.dirname(cert_file))
        with open(cert_file, 'w') as file_handler:
            file_handler.write(cert)
        for dst_addr in self.cert_requests[(cert_isd, cert_ad, cert_version)]:
            new_cert_rep = CertReply.from_values(self.addr, dst_addr, None,
                cert_isd, cert_ad, cert_version, cert)
            self.send(new_cert_rep, dst_addr)
        del self.cert_requests[(cert_isd, cert_ad, cert_version)]

    def process_rot_request(self, rot_req):
        """
        process a ROT request
        """
        isinstance(rot_req, RotRequest)
        logging.info("ROT request received")
        src_addr = rot_req.hdr.src_addr
        path = rot_req.path
        if path is None:
            # TODO: ask PS
            # if still None: return
            pass
        rot_isd = rot_req.rot_isd
        rot_version = rot_req.rot_version
        rot_file = (ISD_PATH + rot_isd + '/ISD:' + rot_isd + '-V:' +
            rot_version + '.crt')
        if not os.path.exists(rot_file):
            logging.info('ROT file %s not found, sending up stream.', rot_isd)
            self.rot_requests.setdefault((rot_isd, rot_version),
                []).append(src_addr)
            dst_addr = get_addr_from_type(PT.ROT_REQ)
            new_rot_req = RotRequest.from_values(PT.ROT_REQ, self.addr,
                dst_addr, path, rot_isd, rot_version)
            self.send(new_rot_req, dst_addr)
        else:
            logging.info('ROT file %s found, sending it back to requester (%s)',
                rot_isd, src_addr)
            with open(rot_file, 'r') as file_handler:
                rot = file_handler.read()
            if rot_req.hdr.path is None or rot_req.hdr.path == b'':
                rot_rep = RotReply.from_values(self.addr, src_addr, None,
                    rot_isd, rot_version, rot)
                self.send(rot_rep, src_addr)
            else:
                path = path.reverse()
                rot_rep = RotReply.from_values(self.addr, src_addr, path,
                    rot_isd, rot_version, rot)
                #rot_rep.hdr.set_downpath()
                (next_hop, port) = self.get_first_hop(rot_rep)
                logging.info("Sending ROT reply, using path: %s", path)
                self.send(rot_rep, next_hop, port)

    def process_rot_reply(self, rot_rep):
        """
        process a ROT reply
        """
        isinstance(rot_rep, RotReply)
        logging.info("ROT reply received")
        rot_isd = rot_rep.rot_isd
        rot_version = rot_rep.rot_version
        rot = rot_rep.rot
        if not self._verify_cert(rot):
            logging.info("ROT verification failed.")
            return
        rot_file = (ISD_PATH + rot_isd + '/ISD:' + rot_isd + '-V:' +
            rot_version + '.crt')
        if not os.path.exists(os.path.dirname(rot_file)):
            os.makedirs(os.path.dirname(rot_file))
        with open(rot_file, 'w') as file_handler:
            file_handler.write(rot)
        for dst_addr in self.rot_requests[(rot_isd, rot_version)]:
            new_rot_rep = RotReply.from_values(self.addr, dst_addr, None,
                rot_isd, rot_version, rot)
            self.send(new_rot_rep, dst_addr)
        del self.rot_requests[(rot_isd, rot_version)]

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        isinstance(packet, SCIONPacket)
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        if ptype == PT.CERT_REQ_LOCAL or ptype == PT.CERT_REQ:
            self.process_cert_request(CertRequest(packet))
        elif ptype == PT.CERT_REP:
            self.process_cert_reply(CertReply(packet))
        elif ptype == PT.ROT_REQ_LOCAL or ptype == PT.ROT_REQ:
            self.process_rot_request(RotRequest(packet))
        elif ptype == PT.ROT_REP:
            self.process_rot_reply(RotReply(packet))
        else:
            logging.info("Type not supported")

def main():
    """
    Main function.
    """
    init_logging()
    if len(sys.argv) != 5:
        logging.error("run: %s IP topo_file conf_file rot_file", sys.argv[0])
        sys.exit()

    cert_server = CertServer(IPv4HostAddr(sys.argv[1]), sys.argv[2],
        sys.argv[3], sys.argv[4])

    logging.info("Started: %s", datetime.datetime.now())
    cert_server.run()

if __name__ == "__main__":
    main()
