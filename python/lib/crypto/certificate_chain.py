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

# External
import lz4

# SCION
from lib.crypto.certificate import Certificate
from lib.crypto.trc import (
    ONLINE_KEY_STRING,
)
from lib.errors import SCIONVerificationError, SCIONParseError
from lib.packet.scion_addr import ISD_AS
from lib.util import iso_timestamp


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
        :param list(Certificate) cert_list: certificate chain as list.
        """
        if len(cert_list) != 2:
            raise SCIONParseError("Certificate chains must have length 2.")
        self.as_cert = cert_list[0]
        self.core_as_cert = cert_list[1]

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
        Perform the entire chain verification. First verifies the AS certificate against the core AS
        certificate, then verifies the core AS certificate against the TRC.

        :param str subject:
            the subject of the first certificate in the certificate chain.
        :param trc: TRC containing all root of trust certificates for one ISD.
        :type trc: :class:`TRC`
        :raises: SCIONVerificationError if the verification fails.
        """
        # Verify AS certificate against core AS certificate
        leaf = self.as_cert
        core = self.core_as_cert
        if leaf.issuing_time < core.issuing_time:
            raise SCIONVerificationError(
                "AS certificate verification failed: Leaf issued before core certificate. Leaf: %s "
                "Core: %s" % (iso_timestamp(leaf.issuing_time), iso_timestamp(core.issuing_time)))
        if leaf.expiration_time > core.expiration_time:
            raise SCIONVerificationError(
                "AS certificate verification failed: Leaf expires after core certificate. Leaf: %s "
                "Core: %s" % (iso_timestamp(leaf.expiration_time),
                              iso_timestamp(core.expiration_time)))
        if not core.can_issue:
            raise SCIONVerificationError(
                "AS certificate verification failed: Core certificate cannot issue certificates")
        try:
            leaf.verify(subject, core.subject_sig_key_raw)
        except SCIONVerificationError as e:
            raise SCIONVerificationError("AS certificate verification failed: %s" % e)
        # Verify core AS certificate against TRC
        if core.expiration_time > trc.exp_time:
            raise SCIONVerificationError(
                "Core AS certificate verification failed: Core certificate expires after TRC. "
                "Core: %s TRC: %s" % (iso_timestamp(core.expiration_time),
                                      iso_timestamp(trc.exp_time)))
        try:
            core.verify(leaf.issuer, trc.core_ases[core.issuer][ONLINE_KEY_STRING])
        except SCIONVerificationError as e:
            raise SCIONVerificationError("Core AS certificate verification failed: %s" % e)

    def get_leaf_isd_as_ver(self):
        isd_as = ISD_AS(self.as_cert.subject)
        return isd_as, self.as_cert.version

    def to_json(self):
        """
        Convert the instance to json format

        :returns: the CertificateChain information.
        :rtype: str
        """
        chain_dict = {}
        index = 0
        for cert in (self.as_cert, self.core_as_cert):
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
