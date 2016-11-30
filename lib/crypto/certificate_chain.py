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
import base64
import copy
import json
import logging

# External
import lz4

# SCION
from lib.crypto.asymcrypto import verify
from lib.crypto.certificate import (
    Certificate,
    SUBJECT_ENC_KEY_STRING,
    SUBJECT_SIG_KEY_STRING,
    SIGNATURE_STRING
)
from lib.packet.scion_addr import ISD_AS


def verify_sig_chain_trc(msg, sig, subject, chain, trc, trc_version):
    """
    Verify whether the packed message with attached signature is validly
    signed by a particular subject belonging to a valid certificate chain.

    :param str msg: message corresponding to the given signature.
    :param bytes sig: signature computed on msg.
    :param str subject: signer identity.
    :param chain: Certificate chain containing the signing entity's certificate.
    :type chain: :class:`CertificateChain`
    :param trc: TRC containing all root of trust certificates for one ISD.
    :type trc: :class:`TRC`
    :param int trc_version: TRC version.

    :returns: True or False whether the verification is successful or not.
    :rtype: bool
    """
    assert isinstance(chain, CertificateChain)
    assert isinstance(trc, TRC)
    if not trc.verify():
        logging.warning('The TRC verification failed.')
        return False
    if not chain.verify(subject, trc, trc_version):
        logging.warning('The certificate chain verification failed.')
        return False
    verifying_key = None
    for signer_cert in chain.certs:
        if signer_cert.subject == subject:
            verifying_key = signer_cert.subject_sig_key
            break
    if verifying_key is None:
        if subject not in trc.core_ases:
            logging.warning('Signer\'s public key has not been found.')
            return False
        verifying_key = trc.core_ases[subject].subject_sig_key
    return verify(msg, sig, verifying_key)



class CertificateChain(object):
    """
    The CertificateChain class contains an ordered sequence of certificates, in
    which: the first certificate is the certificate signed by the core ISD and
    the last is the one at the end of a certificate chain.

    :ivar list certs: (ordered) certificates forming the chain.
    """

    def __init__(self, chain_raw=None, lz4_=False):
        """
        :param str chain_raw: certificate chain as json string.
        """
        self.certs = []
        if chain_raw:
            self._parse(chain_raw, lz4_)

    def _parse(self, chain_raw, lz4_):
        """
        Parse a certificate chain file and populate the instance's attributes.

        :param str chain_raw: certificate chain as json string.
        """
        if lz4_:
            chain_raw = lz4.loads(chain_raw).decode("utf-8")
        chain = json.loads(chain_raw)
        for index in range(1, len(chain) + 1):
            cert_dict = chain[str(index)]
            cert_dict[SUBJECT_SIG_KEY_STRING] = \
                base64.b64decode(cert_dict[SUBJECT_SIG_KEY_STRING])
            cert_dict[SUBJECT_ENC_KEY_STRING] = \
                base64.b64decode(cert_dict[SUBJECT_ENC_KEY_STRING])
            cert_dict[SIGNATURE_STRING] = \
                base64.b64decode(cert_dict[SIGNATURE_STRING])
            cert = Certificate.from_dict(cert_dict)
            self.certs.append(cert)

    @classmethod
    def from_values(cls, cert_list):
        """
        Generate a CertificateChain instance.

        :param list cert_list:
            (ordered) certificates to populate the chain with.
        :returns: the newly created CertificateChain instance.
        :rtype: :class:`CertificateChain`
        """
        cert_chain = CertificateChain()
        cert_chain.certs = cert_list
        return cert_chain


    def verify(self, trc):
        """
        Perform the entire chain verification.

        :param trc: TRC containing all root of trust certificates for one ISD.
        :type trc: :class:`TRC`
        :returns: True or False whether the verification succeeds or fails.
        :rtype: bool
        """
        if len(self.certs) == 0:
            logging.warning("The certificate chain is not initialized.")
            return False
        issuer_cert = self.certs[0]
        if not issuer_cert.subject == issuer_cert.issuer:
            logging.error("This certificate is not signed by a core AS")
            return False
        if not issuer_cert.issuer in trc.core_ases:
            logging.error("This certificate is not signed by a core AS")
            return False
        if not issuer_cert.verify(trc.core_ases[issuer_cert.issuer]):
            return False
        for cert in self.certs[1:]:
            if not cert.verify(issuer_cert):
                return False
            issuer_cert = cert
        return True

    def get_leaf_isd_as_ver(self):
        if not self.certs:
            return None
        leaf_cert = self.certs[0]
        isd_as = ISD_AS(leaf_cert.subject)
        return isd_as, leaf_cert.version

    def to_json(self):
        """
        Convert the instance to json format.

        :returns: the CertificateChain information.
        :rtype: str
        """
        chain_dict = {}
        index = 1
        for cert in self.certs:
            cert_dict = copy.deepcopy(cert.get_cert_dict(True))
            cert_dict[SUBJECT_SIG_KEY_STRING] = \
                base64.b64encode(cert_dict[SUBJECT_SIG_KEY_STRING]).decode('utf-8')
            cert_dict[SUBJECT_ENC_KEY_STRING] = \
                base64.b64encode(cert_dict[SUBJECT_ENC_KEY_STRING]).decode('utf-8')
            cert_dict[SIGNATURE_STRING] = \
                base64.b64encode(cert_dict[SIGNATURE_STRING]).decode('utf-8')
            chain_dict[index] = cert_dict
            index += 1
        chain_str = json.dumps(chain_dict, sort_keys=True, indent=4)
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
