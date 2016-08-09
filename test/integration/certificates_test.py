#!/usr/bin/python3
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
:mod:`certificates_test` --- SCION certificates integration test
================================================================
"""
# Stdlib
import base64
import logging
import os
import select
import socket

# External packages
import nose
from external.ipaddress import IPv4Address

# SCION
from lib.crypto.asymcrypto import sign
from lib.crypto.certificate import CertificateChain, TRC, verify_sig_chain_trc
from lib.defines import SCION_BUFLEN, SCION_UDP_PORT
from lib.packet.scion import (
    CertChainReply,
    CertChainRequest,
    PacketType as PT,
    TRCReply,
    TRCRequest,
)
from lib.packet.scion_addr import SCIONAddr
from lib.topology import Topology
from lib.util import (
    get_cert_chain_file_path,
    get_sig_key_file_path,
    get_trc_file_path,
    read_file,
    write_file,
)


class TestCertificates(object):
    """
    Unit tests for certificate.py and asymcrypto.py.
    """

    def test(self):
        """
        Create a certificate chain and verify it with a TRC file. Sign a message
        with the private key of the last certificate in the chain and verify it.
        """
        cert10 = CertificateChain(get_cert_chain_file_path(1, 10, 1, 10, 0))
        trc = TRC(get_trc_file_path(1, 10, 1, 0))
        print('TRC verification', trc.verify())
        print('Cert Chain verification:', cert10.verify('ISD:1-AD:10', trc, 0))

        sig_priv10 = read_file(get_sig_key_file_path(1, 10))
        sig_priv10 = base64.b64decode(sig_priv10)
        msg = b'abcd'
        sig = sign(msg, sig_priv10)
        print('Sig test:', verify_sig_chain_trc(msg, sig, 'ISD:1-AD:10', cert10,
                                                trc, 0))

        sig_priv13 = read_file(get_sig_key_file_path(1, 13))
        sig_priv13 = base64.b64decode(sig_priv13)
        msg = b'abd'
        sig = sign(msg, sig_priv13)
        CertificateChain.from_values([])
        print('Sig test 2:', verify_sig_chain_trc(msg, sig, 'ISD:1-AD:13',
                                                  cert10, trc, 0), '\n')

        topology = Topology.from_file(
            "topology/ISD1/topologies/ISD:1-AD:10.json")
        src_addr = SCIONAddr.from_values(topology.isd_id, topology.ad_id,
                                         IPv4Address("127.0.0.1"))
        dst_addr = topology.certificate_servers[0].addr
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((str(src_addr.host_addr), SCION_UDP_PORT))

        print("Sending TRC request (ISD:1-V:0) to local CS.")
        msg = TRCRequest.from_values(
            PT.TRC_REQ_LOCAL, src_addr,
            topology.parent_border_routers[0].interface.if_id,
            topology.isd_id, topology.ad_id, 1, 0).pack()
        sock.sendto(msg, (str(dst_addr), SCION_UDP_PORT))

        temp_file = './temp.txt'
        timeout = 5

        ready = select.select([sock], [], [], timeout)
        if not ready[0]:
            print("Error: no TRC reply was received!")
            sock.close()
            return

        data, _ = sock.recvfrom(SCION_BUFLEN)
        print("Received TRC reply from local CS.")
        trc_reply = TRCReply(data)
        write_file(temp_file, trc_reply.trc.decode('utf-8'))
        trc = TRC(temp_file)
        assert trc.verify()

        print("Sending cert chain request (ISD:1-AD:16-V:0) to local CS.")
        msg = CertChainRequest.from_values(
            PT.CERT_CHAIN_REQ_LOCAL, src_addr,
            topology.parent_border_routers[0].interface.if_id,
            topology.isd_id, topology.ad_id, 1, 16, 0).pack()
        sock.sendto(msg, (str(dst_addr), SCION_UDP_PORT))

        ready = select.select([sock], [], [], timeout)
        if not ready[0]:
            print("Error: no cert chain reply was received!")
            sock.close()
            return

        data, _ = sock.recvfrom(SCION_BUFLEN)
        print("Received cert chain reply from local CS.")
        cert_chain_reply = CertChainReply(data)
        write_file(temp_file, cert_chain_reply.cert_chain.decode('utf-8'))
        cert_chain = CertificateChain(temp_file)
        assert cert_chain.verify('ISD:1-AD:16', trc, 0)

        os.remove(temp_file)
        sock.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    nose.run(defaultTest=__name__)
