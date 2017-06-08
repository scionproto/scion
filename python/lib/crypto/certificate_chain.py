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
===========================================================
"""
# Stdlib
import json
import os

# External
import lz4

# SCION
from lib.crypto.asymcrypto import verify
from lib.crypto.certificate import Certificate
from lib.crypto.trc import (
    ONLINE_KEY_STRING,
    TRC,
)
from lib.crypto.util import CERT_DIR
from lib.errors import SCIONVerificationError
from lib.packet.scion_addr import ISD_AS


def get_cert_chain_file_path(conf_dir, isd_as, version):  # pragma: no cover
    """
    Return the certificate chain file path for a given ISD.
    """
    return os.path.join(conf_dir, CERT_DIR, 'ISD%s-AS%s-V%s.crt' % (isd_as[0], isd_as[1], version))


def verify_sig_chain_trc(msg, sig, subject, chain, trc):
    """
    Verify whether the packed message with attached signature is validly
    signed by a particular subject belonging to a valid certificate chain.

    :param bytes msg: message corresponding to the given signature.
    :param bytes sig: signature computed on msg.
    :param ISD_AS subject: signer identity.
    :param CertificateChain chain: Certificate chain containing the signing entity's certificate.
    :param TRC trc: Issuing TRC containing all root of trust certificates for one ISD.

    :raises: SCIONVerificationError if the verification fails.
    """
    assert isinstance(chain, CertificateChain)
    assert isinstance(trc, TRC)
    subject = str(subject)
    try:
        chain.verify(subject, trc)
    except SCIONVerificationError as e:
        raise SCIONVerificationError("The certificate chain verification failed:\n%s" % e)
    verifying_key = None
    for signer_cert in chain.certs:
        if signer_cert.subject == subject:
            verifying_key = signer_cert.subject_sig_key_raw
            break
    if verifying_key is None:
        if subject not in trc.core_ases:
            raise SCIONVerificationError("Signer's public key has not been found: %s" % subject)
        verifying_key = trc.core_ases[subject].subject_sig_key_raw
    verify(msg, sig, verifying_key)


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
        :raises: SCIONVerificationError if the verification fails.
        """
        if not self.certs:
            raise SCIONVerificationError("The certificate chain is not initialized.")
        cert = self.certs[0]
        for issuer_cert in self.certs[1:]:
            if issuer_cert.subject == subject:
                break
            cert.verify(subject, issuer_cert)
            cert = issuer_cert
            subject = cert.subject
        # First check whether a root cert was added to the chain.
        if cert.issuer != subject:
            raise SCIONVerificationError("Root Certificate added to chain:\n%s" % cert)
        # Try to find a root cert in the trc.
        try:
            cert.verify_core(trc.core_ases[cert.issuer][ONLINE_KEY_STRING])
        except SCIONVerificationError:
            raise SCIONVerificationError("Core AS certificate verification failed.")

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
