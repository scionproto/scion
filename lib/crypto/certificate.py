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
import logging
import time

# SCION
from lib.crypto.asymcrypto import sign, verify

SUBJECT_STRING = 'Subject'
ISSUER_STRING = 'Issuer'
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
    :ivar str issuer: the certificate issuer. It can only be an AS.
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
    :cvar int validity_period:
        default validity period (in real seconds) of a new certificate.
    :cvar str sign_algortihm: default algorithm used to sign a certificate.
    :cvar str enc_alorithm: default algorithm used to encrypt messages.
    """

    VALIDITY_PERIOD = 365 * 24 * 60 * 60
    SIGN_ALGORTIHM = 'ed25519'
    ENC_ALGORITHM = 'curve25519xsalsa20poly1305'
    FIELDS_MAP = {
        SUBJECT_STRING: ("subject", str),
        ISSUER_STRING: ("issuer", str),
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

    def verify(self, subject, issuer_cert):
        """
        Perform one step verification.

        :param str subject:
            the certificate subject. It can either be an AS, an email address or
            a domain address.
        :param str issuer_cert: the certificate issuer. It can only be an AS.
        :returns: True or False whether the verification succeeds or fails.
        :rtype: bool
        """
        if subject != self.subject:
            logging.error("The given subject(%s) doesn't match the \
            certificate's subject(%s)" % (str(subject), str(self.subject)))
            return False
        if not self._verify_signature(self.signature_raw,
                                      issuer_cert.subject_sig_key_raw):
            logging.error("Signature verification failed.")
            return False
        if int(time.time()) >= self.expiration_time:
            logging.error("This certificate expired.")
            return False
        if int(time.time()) >= issuer_cert.expiration_time:
            logging.error("The issuer certificate expired.")
            return False
        return True

    def verify_core(self, pub_online_root_key):
        """
        Verify core signature with given online root key.

        :param bytes pub_online_root_key:
            The online root key of the core AS  which signed this
            root certificate
        :returns: True or False whether the verification succeeds or fails.
        :rtype: bool
        """
        return self._verify_signature(self.signature_raw, pub_online_root_key)

    def _verify_signature(self, signature, public_key):
        """
        Checks if the signature can be verified with the given public key
        """
        return verify(self._sig_input(), signature, public_key)

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
    def from_values(cls, subject, issuer, version, comment, can_issue,
                    subject_enc_key, subject_sig_key, iss_priv_key):
        """
        Generate a Certificate instance.

        :param str subject:
            the certificate subject. It can either be an AS, an email address or
            a domain address.
        :param bytes subject_sig_key: the public key of the subject.
        :param bytes subject_enc_key: the public part of the encryption key.
        :param str issuer: the certificate issuer. It can only be an AS.
        :param bytes iss_priv_key:
            the issuer's private key. It is used to sign the certificate.
        :param int version: the certificate version.
        :returns: the newly created Certificate instance.
        :rtype: :class:`Certificate`
        """
        now = int(time.time())
        cert_dict = {
            SUBJECT_STRING: subject,
            ISSUER_STRING: issuer,
            VERSION_STRING: version,
            COMMENT_STRING: comment,
            CAN_ISSUE_STRING: can_issue,
            ISSUING_TIME_STRING: now,
            EXPIRATION_TIME_STRING: now + cls.VALIDITY_PERIOD,
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
        for k in d:
            if self.FIELDS_MAP[k][1] == str:
                d[k] = base64.b64encode(d[k].encode('utf-8')).decode('utf-8')
        j = json.dumps(d, sort_keys=True, separators=(',', ':'))
        return j.encode('utf-8')

    def to_json(self, indent=4):
        return json.dumps(self.dict(), sort_keys=True, indent=indent)

    def __str__(self):
        return self.to_json(None)

    def __eq__(self, other):  # pragma: no cover
        return str(self) == str(other)
