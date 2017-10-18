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
:mod:`certificate` --- SCION certificate parser
===============================================
"""
# Stdlib
import base64
import json
import time

# SCION
from lib.crypto.asymcrypto import sign, verify
from lib.errors import SCIONVerificationError

SUBJECT_STRING = 'Subject'
ISSUER_STRING = 'Issuer'
TRC_VERSION_STRING = "TRCVersion"
VERSION_STRING = 'Version'
COMMENT_STRING = 'Comment'
CAN_ISSUE_STRING = 'CanIssue'
ISSUING_TIME_STRING = 'IssuingTime'
EXPIRATION_TIME_STRING = 'ExpirationTime'
ENC_ALGORITHM_STRING = 'EncAlgorithm'
SUBJECT_ENC_KEY_STRING = 'SubjectEncKey'
SIGN_ALGORITHM_STRING = 'SignAlgorithm'
SUBJECT_SIG_KEY_STRING = 'SubjectSigKey'
SIGNATURE_STRING = 'Signature'


class Certificate(object):
    """
    The Certificate class parses a certificate of an AS and stores such
    information for further use.

    :ivar str subject: the certificate subject.
    :ivar str issuer: the certificate issuer. It can only be a core AS.
    :ivar int trc_version: the version of the issuing trc.
    :ivar int version: the certificate version.
    :ivar str comment: is an arbitrary and optional string used by the subject
        to describe the certificate
    :ivar bool can_issue: describes whether the subject is able to issue
        certificates
    :ivar int issuing_time: the time at which the certificate was created.
    :ivar int expiration_time: the time at which the certificate expires.
    :ivar str enc_algorithm: the algorithm used to encrypt messages.
    :ivar bytes subject_enc_key: the public key used for decryption.
    :ivar str sign_algorithm: the algorithm used to sign the certificate.
    :ivar bytes subject_sig_key: the public key used for signing.
    :ivar bytes signature: the certificate signature. It is computed over the
        rest of the certificate.
    :cvar int as_validity_period:
        default validity period (in real seconds) of a new regular AS certificate.
    :cvar int core_as_validity_period:
        default validity period (in real seconds) of a new core AS certificate.
    :cvar str sign_algortihm: default algorithm used to sign a certificate.
    :cvar str enc_alorithm: default algorithm used to encrypt messages.
    """
    AS_VALIDITY_PERIOD = 365 * 24 * 60 * 60
    CORE_AS_VALIDITY_PERIOD = 365 * 24 * 60 * 60
    SIGN_ALGORTIHM = 'ed25519'
    ENC_ALGORITHM = 'curve25519xsalsa20poly1305'
    FIELDS_MAP = {
        SUBJECT_STRING: ("subject", str),
        ISSUER_STRING: ("issuer", str),
        TRC_VERSION_STRING: ("trc_version", int),
        VERSION_STRING: ("version", int),
        COMMENT_STRING: ("comment", str),
        CAN_ISSUE_STRING: ("can_issue", bool),
        ISSUING_TIME_STRING: ("issuing_time", int),
        EXPIRATION_TIME_STRING: ("expiration_time", int),
        ENC_ALGORITHM_STRING: ("enc_algorithm", str),
        SUBJECT_ENC_KEY_STRING: ("subject_enc_key", bytes),
        SIGN_ALGORITHM_STRING: ("sign_algorithm", str),
        SUBJECT_SIG_KEY_STRING: ("subject_sig_key", bytes),
        SIGNATURE_STRING: ("signature", bytes),
    }

    def __init__(self, cert_dict):
        """
        :param certificate_file: the name of the certificate file.
        :type certificate_file: str
        """
        for k, (name, type_) in self.FIELDS_MAP.items():
            val = cert_dict[k]
            if type_ in (int,):
                val = int(val)
            setattr(self, name, val)
        self.subject_enc_key_raw = base64.b64decode(self.subject_enc_key)
        self.subject_sig_key_raw = base64.b64decode(self.subject_sig_key)
        self.signature_raw = base64.b64decode(self.signature)

    def verify(self, subject, verifying_key):
        """
        Perform one step verification.

        :param str subject:
            the certificate subject. It can either be an AS, an email address or
            a domain address.
        :param bytes verifying_key: the key to be used for signature verification.
        :raises: SCIONVerificationError if the verification fails.
        """
        if subject != self.subject:
            raise SCIONVerificationError(
                "The given subject (%s) doesn't match the certificate's subject (%s):\n%s" %
                (subject, self.subject, self))
        if int(time.time()) >= self.expiration_time:
            raise SCIONVerificationError("This certificate expired:\n%s" % self)
        try:
            self._verify_signature(self.signature_raw, verifying_key)
        except SCIONVerificationError:
            raise SCIONVerificationError("Signature verification failed:\n%s" % self)

    def _verify_signature(self, signature, public_key):
        """
        Checks if the signature can be verified with the given public key
        """
        verify(self._sig_input(), signature, public_key)

    def dict(self, with_signature=True):
        """
        Return the certificate information.

        :param bool with_signature:
            tells whether the signature must also be included in the returned
            data.
        :returns: the certificate information.
        :rtype: dict
        """
        cert_dict = {}
        for k, (name, _) in self.FIELDS_MAP.items():
            cert_dict[k] = getattr(self, name)
        if not with_signature:
            del cert_dict[SIGNATURE_STRING]
        return cert_dict

    def sign(self, iss_priv_key):
        data = self._sig_input()
        self.signature_raw = sign(data, iss_priv_key)
        self.signature = base64.b64encode(self.signature_raw).decode('utf-8')

    @classmethod
    def from_values(cls, subject, issuer, trc_version, version, comment, can_issue, validity_period,
                    subject_enc_key, subject_sig_key, iss_priv_key):
        """
        Generate a Certificate instance.

        :param str subject:
            the certificate subject. It can either be an AS, an email address or
            a domain address.
        :param str issuer: the certificate issuer. It can only be an AS.
        :param int trc_version: the version of the issuing certificate/trc.
        :param int version: the certificate version.
        :param str comment: a comment describing the certificate.
        :param bool can_issue:
            states whether the subject is allowed to issue certificates for other ASes.
        :param int validity_period: the validity period after creation of this certificate.
        :param bytes iss_priv_key:
            the issuer's signing key. It is used to sign the certificate.
        :param bytes subject_sig_key: the public key of the subject.
        :param bytes subject_enc_key: the public part of the encryption key.
        :returns: the newly created Certificate instance.
        :rtype: :class:`Certificate`
        """
        now = int(time.time())
        cert_dict = {
            SUBJECT_STRING: subject,
            ISSUER_STRING: issuer,
            TRC_VERSION_STRING: trc_version,
            VERSION_STRING: version,
            COMMENT_STRING: comment,
            CAN_ISSUE_STRING: can_issue,
            ISSUING_TIME_STRING: now,
            EXPIRATION_TIME_STRING: now + validity_period,
            ENC_ALGORITHM_STRING: cls.ENC_ALGORITHM,
            SUBJECT_ENC_KEY_STRING:
                base64.b64encode(subject_enc_key).decode("utf-8"),
            SIGN_ALGORITHM_STRING: cls.SIGN_ALGORTIHM,
            SUBJECT_SIG_KEY_STRING:
                base64.b64encode(subject_sig_key).decode("utf-8"),
            SIGNATURE_STRING: "",
        }
        cert = Certificate(cert_dict)
        cert.sign(iss_priv_key)
        return cert

    def _sig_input(self):
        d = self.dict(False)
        j = json.dumps(d, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        return j.encode('utf-8')

    def to_json(self, indent=4):
        return json.dumps(self.dict(), sort_keys=True, indent=indent)

    def __str__(self):
        return self.to_json(None)

    def __eq__(self, other):  # pragma: no cover
        return str(self) == str(other)
