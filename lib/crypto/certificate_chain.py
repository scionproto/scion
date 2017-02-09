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
:mod:`certificate_chain` --- SCION certificate_chain parser
===============================================
"""
# Stdlib
import json
import logging

# External
import lz4

# SCION
from lib.crypto.asymcrypto import verify
from lib.crypto.certificate import Certificate
from lib.crypto.trc import (
    ONLINE_KEY_STRING,
    TRC,
)
from lib.packet.scion_addr import ISD_AS


def verify_sig_chain_trc(msg, sig, subject, chain, trc, trc_ver):
    """
    Verify whether the packed message with attached signature is validly
    signed by a particular subject belonging to a valid certificate chain.

    :param str msg: message corresponding to the given signature.
    :param bytes sig: signature computed on msg.
    :param str subject: signer identity.
    :param chain: Certificate chain containing the signing entity's certificate.
    :type chain: :class:`CertificateChain`
    :param trc: Current TRC containing all root of trust certificates for
        one ISD.
    :type trc: :class:`TRC`
    :param trc_ver: The TRCs version

    :returns: True or False whether the verification is successful or not.
    :rtype: bool
    """
    assert isinstance(chain, CertificateChain)
    assert isinstance(trc, TRC)
    if not chain.verify(subject, trc):
        logging.error("The certificate chain verification failed.")
        return False
    verifying_key = None
    for signer_cert in chain.certs:
        if signer_cert.subject == subject:
            verifying_key = signer_cert.subject_sig_key_raw
            break
    if verifying_key is None:
        if subject not in trc.core_ases:
            logging.error("Signer's public key has not been found.")
            return False
        verifying_key = trc.core_ases[subject].subject_sig_key_raw
    return verify(msg, sig, verifying_key)


class CertificateChain(object):
    """
    The CertificateChain class contains an ordered sequence of certificates, in
    which: the first certificate is the one at the end of a certificate chain
    and the last is the certificate signed by the core ISD. Therefore, starting
    from the first one, each certificate should be verified by the next one in
    the sequence.

    :ivar list certs: (ordered) certificates forming the chain.
    """

    def __init__(self, cert_list):
        """
        :param str cert_list: certificate chain as list.
        """
        self.certs = cert_list

    @classmethod
    def from_raw(cls, chain_raw, lz4_=False):
        if lz4_:
            chain_raw = lz4.loads(chain_raw).decode("utf-8")
        chain = json.loads(chain_raw)
        certs = []
        for k in sorted(chain):
            cert = Certificate(chain[k])
            certs.append(cert)
        return CertificateChain(certs)

    def verify(self, subject, trc):
        """
        Perform the entire chain verification. It verifies each pair and at the
        end verifies the last certificate of the chain with the root certificate
        that was used to sign it.

        :param str subject:
            the subject of the first certificate in the certificate chain.
        :param trc: TRC containing all root of trust certificates for one ISD.
        :type trc: :class:`TRC`
        :returns: True or False whether the verification succeeds or fails.
        :rtype: bool
        """
        if not self.certs:
            logging.error("The certificate chain is not initialized.")
            return False
        cert = self.certs[0]
        for issuer_cert in self.certs[1:]:
            if issuer_cert.subject == subject:
                break
            if not cert.verify(subject, issuer_cert):
                return False
            cert = issuer_cert
            subject = cert.subject
        # First check whether a root cert was added to the chain.
        if cert.issuer != subject:
            return False
        # Try to find a root cert in the trc.
        if not cert.verify_core(trc.core_ases[cert.issuer][ONLINE_KEY_STRING]):
            logging.error("Core AS certificate verification failed.")
            return False
        return True

    def get_leaf_isd_as_ver(self):
        if not self.certs:
            return None
        leaf_cert = self.certs[0]
        isd_as = ISD_AS(leaf_cert.subject)
        return isd_as, leaf_cert.version

    def to_json(self):
        """
        Convert the instance to json format

        :returns: the CertificateChain information.
        :rtype: str
        """
        chain_dict = {}
        index = 0
        for cert in self.certs:
            chain_dict[index] = cert.dict(True)
            index += 1
        chain_str = json.dumps(chain_dict, indent=4)
        return chain_str

    def pack(self, lz4_=False):
        ret = self.to_json().encode('utf-8')
        if lz4_:
            return lz4.dumps(ret)
        return ret

    def __len__(self):
        return len(self.pack())

    def __str__(self):
        return self.to_json()

    def __eq__(self, other):  # pragma: no cover
        return str(self) == str(other)
