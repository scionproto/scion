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
from lib.packet.pcb import *
from lib.packet.opaque_field import *
from lib.packet.path import EmptyPath 
from lib.packet.scion import SCIONPacket, IFIDRequest, IFIDReply, get_type,\
        Beacon, PathRequest, PathRecord, PathInfo
from lib.packet.scion import PacketType as PT
from lib.topology import ElementType, NeighborType
from infrastructure.server import ServerBase, SCION_UDP_PORT, SCION_UDP_PS2EH_PORT 
import socket, sys, hashlib


class CertServer(ServerBase):
    """
    The SCION Certificate Server.
    """
    def __init__(self, addr, topo_file, config_file, rot_file):
        ServerBase.__init__(self, addr, topo_file, config_file, rot_file)
        self.cert_requests = {}
        self.rot_requests = {}

    def process_cert_request(self, packet):
        """
        Process a certificate request
        """
        print("Cert request received")
        cert_req = CertRequest(packet)
        src_addr = cert_req.hdr.src_addr
        path = cert_req.path
        if path == None:
            # ask PS
            # if still None: return
            pass
        cert_isd = cert_req.cert_isd
        cert_ad = cert_req.cert_ad
        cert_version = cert_req.cert_version
        target_key = cert_isd + cert_ad + cert_version
        target_key = target_key.encode('utf-8')
        target_key = hashlib.sha256(target_key).hexdigest()
        cert_file = '../topology/ISD' + cert_isd + \
                    '/certificates/isd' + cert_isd + \
                    '-ad' + cert_ad + '-' + cert_version + '.crt'
        if os.path.exists(cert_file) == False:
            print('CS (%s:%s): certificate %s:%s not found, sending up stream.' % \
                  self.topology.isd_id, self.topology.ad_id, cert_isd, cert_ad)
            self.cert_requests.setdefault(target_key,[]).append(src_addr)
            dst_addr = get_addr_from_type(PT.CERT_REQ)
            new_cert_req = CertRequest.from_values(PT.CERT_REQ, self.addr, dst_addr, path, cert_isd, cert_ad, cert_version)
            self.send(new_cert_req, dst_addr)
        else:
            print('CS (%s:%s): certificate %s:%s found, sending it back to \
                  requester (%s)' % self.topology.isd_id, self.topology.ad_id,
                  cert_isd, cert_ad, src_addr)
            f = open(cert_file, 'r')
            cert = f.read()
            f.close()
            if cert_req.hdr.path == None or cert_req.hdr.path == '':
                """ Either local req or user req """
                cert_rep = CertRep.from_values(self.addr, src_addr, None, cert_isd, cert_ad, cert_version, cert)
                self.send(cert_rep, src_addr)
            else:
                """ Remote req """
                path = path.reverse()
                cert_rep = CertRep.from_values(self.addr, src_addr, path, cert_isd, cert_ad, cert_version, cert)
                #cert_rep.hdr.set_downpath()
                (next_hop, port) = self.get_first_hop(cert_rep)
                print ("Sending cert reply, using path:", path, next_hop)
                self.send(cert_rep, next_hop, port)
          
    def process_cert_reply(self, packet):
        """
        process a certificate reply
        """
        print("Cert reply received")
        cert_rep = CertRep(packet)
        cert_isd = cert_rep.cert_isd
        cert_ad = cert_rep.cert_ad
        cert_version = cert_rep.cert_version
        cert = cert_rep.cert
        if self._verify_cert(cert) == False:
            print("CS (%s:%s): certificate verification failed." % \
                  self.topology.isd_id, self.topology.ad_id)
            return
        target_key = cert_isd + cert_ad + cert_version
        target_key = target_key.encode('utf-8')
        target_key = hashlib.sha256(target_key).hexdigest()
        for dst_addr in self.cert_requests[target_key]:
            new_cert_rep = CertRep.from_values(self.addr, dst_addr, None, cert_isd, cert_ad, cert_version, cert)
            self.send(new_cert_rep, dst_addr)
        del self.cert_requests[target_key]

    def process_rot_request(self, packet):
        """
        process a ROT request
        """
        print("ROT request received")
        rot_req = RotRequest(packet)
        src_addr = rot_req.hdr.src_addr
        path = rot_req.path
        if path == None:
            # ask PS
            # if still None: return
            pass
        rot_isd = rot_req.rot_isd
        rot_version = rot_req.rot_version
        target_key = rot_isd + rot_version
        target_key = target_key.encode('utf-8')
        target_key = hashlib.sha256(target_key).hexdigest()
        rot_file = '../topology/ISD' + rot_isd + \
                    '/rot-isd' + rot_isd + \
                    '-' + rot_version + '.xml'
        if os.path.exists(rot_file) == False:
            print('CS (%s:%s): ROT file %s not found, sending up stream.' % \
                  self.topology.isd_id, self.topology.ad_id, rot_isd)
            self.rot_requests.setdefault(target_key,[]).append(src_addr)
            dst_addr = get_addr_from_type(PT.ROT_REQ)
            new_rot_req = RotRequest.from_values(PT.ROT_REQ, self.addr, dst_addr, path, rot_isd, rot_version)
            self.send(new_rot_req, dst_addr)
        else:
            print('CS (%s:%s): ROT file %s found, sending it back to \
                  requester (%s)' % self.topology.isd_id, self.topology.ad_id,
                  rot_isd, src_addr)
            f = open(rot_file, 'r')
            rot = f.read()
            f.close()
            if rot_req.hdr.path == None or rot_req.hdr.path == '':
                """ Either local req or user req """
                rot_rep = RotRep.from_values(self.addr, src_addr, None, rot_isd, rot_version, rot)
                self.send(rot_rep, src_addr)
            else:
                """ Remote req """
                path = path.reverse()
                rot_rep = RotRep.from_values(self.addr, src_addr, path, rot_isd, rot_version, rot)
                #rot_rep.hdr.set_downpath()
                (next_hop, port) = self.get_first_hop(rot_rep)
                print ("Sending ROT reply, using path:", path, next_hop)
                self.send(rot_rep, next_hop, port)

    def process_rot_reply(self, packet):
        """
        process a ROT reply
        """
        print("ROT reply received")
        rot_rep = RotRep(packet)
        rot_isd = rot_rep.rot_isd
        rot_version = rot_rep.rot_version
        rot = rot_rep.rot
        if self._verify_cert(rot) == False:
            print("CS (%s:%s): ROT verification failed." % \
                  self.topology.isd_id, self.topology.ad_id)
            return
        target_key = rot_isd + rot_version
        target_key = target_key.encode('utf-8')
        target_key = hashlib.sha256(target_key).hexdigest()
        for dst_addr in self.rot_requests[target_key]:
            new_rot_rep = RotRep.from_values(self.addr, dst_addr, None, rot_isd, rot_version, rot)
            self.send(new_rot_rep, dst_addr)
        del self.rot_requests[target_key]

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        if ptype == PT.CERT_REQ_LOCAL or ptype == PT.CERT_REQ:
            self.process_cert_request(packet)
        elif ptype == PT.CERT_REP:
            self.process_cert_reply(packet)
        elif ptype == PT.ROT_REQ_LOCAL or ptype == PT.ROT_REQ:
            self.process_rot_request(packet)
        elif ptype == PT.ROT_REP:
            self.process_rot_reply(packet)
        else: 
            print("Type not supported")

def main():
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv)!=5:
        print("run: %s IP topo_file conf_file rot_file" %sys.argv[0])
        sys.exit()
    cs=CertServer(IPv4HostAddr(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4])
    cs.run()

if __name__ == "__main__":
    main()
