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
import copy
import json
import logging
import time

# SCION
from lib.crypto.asymcrypto import sign, verify
from lib.util import load_json_file

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

    :ivar str subject:
        the certificate subject. It can either be an AS, an email address or a
        domain address.
    :ivar str issuer: the certificate issuer. It can only be an AS.
    :ivar int version: the certificate version.
    :ivar str comment: is an arbitrary and optional string used by the subject
        to describe the certificate
    :ivar bool can_issue: describes whether the subject is able to issue
        certificates
    :ivar int issuing_time: the time at which the certificate was created.
    :ivar int expiration_time: the time at which the certificate expires.
    :ivar str enc_algorithm: the algorithm used to encrypt messages.
    :ivar bytes subject_enc_key: the public part of the encryption key.
    :ivar str sign_algorithm: the algorithm used to sign the certificate.
    :ivar bytes subject_sig_key: the public key of the subject.
    :ivar bytes signature:
        the certificate signature. It is computed over the rest of the
        certificate.
    :cvar int VALIDITY_PERIOD:
        default validity period (in real seconds) of a new certificate.
    :cvar str SIGN_ALGORITHM: default algorithm used to sign a certificate.
    :cvar str ENCRYPT_ALGORITHM: default algorithm used to encrypt messages.
    """

    VALIDITY_PERIOD = 365 * 24 * 60 * 60
    SIGN_ALGORITHM = 'ed25519'
    ENCRYPT_ALGORITHM = 'curve25519xsalsa20poly1305'

    def __init__(self, json_string=None):
        """
        :param certificate_file: the name of the certificate file.
        :type certificate_file: str
        """
        self.subject = ''
        self.issuer = ''
        self.version = 0
        self.comment = ''
        self.can_issue = False
        self.issuing_time = 0
        self.expiration_time = 0
        self.enc_algorithm = ''
        self.subject_enc_key = b''
        self.sign_algorithm = ''
        self.subject_sig_key = b''
        self.signature = b''
        if json_string:
            self.parse(json_string)

    @classmethod
    def from_dict(cls, cert_dict):
        """
        Generate a Certificate instance.

        :param dict cert_dict:
            dictionary containing the certificate information.
        :returns: the newly created Certificate instance.
        :rtype: :class:`Certificate`
        """
        cert = Certificate()
        try:
            cert.subject = cert_dict[SUBJECT_STRING]
            cert.issuer = cert_dict[ISSUER_STRING]
            cert.version = cert_dict[VERSION_STRING]
            cert.comment = cert_dict[COMMENT_STRING]
            cert.can_issue = cert_dict[CAN_ISSUE_STRING]
            cert.issuing_time = cert_dict[ISSUING_TIME_STRING]
            cert.expiration_time = cert_dict[EXPIRATION_TIME_STRING]
            cert.encryption_algorithm = cert_dict[ENC_ALGORITHM_STRING]
            cert.subject_enc_key = cert_dict[SUBJECT_ENC_KEY_STRING]
            cert.sign_algorithm = cert_dict[SIGN_ALGORITHM_STRING]
            cert.subject_sig_key = cert_dict[SUBJECT_SIG_KEY_STRING]
            cert.signature = cert_dict[SIGNATURE_STRING]
        except KeyError as inst:
            logging.ERROR("Key Error: s" % inst)
        return cert

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
        if int(time.time()) >= self.expiration_time:
            logging.error("This certificte expired.")
            return False
        if int(time.time()) >= issuer_cert.expiration_time:
            logging.error("The issuer certificate expired.")
            return False
        if subject != self.subject:
            logging.warning("The given subject doesn't match the \
            certificate's subject")
            return False
        if not self._verify_signature(self.signature,
                                      issuer_cert.subject_sig_key):
            return False
        return True

    def _verify_signature(self, signature, public_key):
        """
        Checks if the signature can be verified with the given public key
        """
        msg = self.__str__(with_signature=False).encode('utf-8')
        return verify(msg, signature, public_key)

    def get_cert_dict(self, with_signature):
        """
        Return the certificate information.

        :param bool with_signature:
            tells whether the signature must also be included in the returned
            data.
        :returns: the certificate information.
        :rtype: dict
        """
        cert_dict = {SUBJECT_STRING: self.subject,
                     ISSUER_STRING: self.issuer,
                     VERSION_STRING: self.version,
                     COMMENT_STRING: self.comment,
                     CAN_ISSUE_STRING: self.can_issue,
                     ISSUING_TIME_STRING: self.issuing_time,
                     EXPIRATION_TIME_STRING: self.expiration_time,
                     ENC_ALGORITHM_STRING: self.encryption_algorithm,
                     SUBJECT_ENC_KEY_STRING: self.subject_enc_key,
                     SIGN_ALGORITHM_STRING: self.sign_algorithm,
                     SUBJECT_SIG_KEY_STRING: self.subject_sig_key}
        if with_signature:
            cert_dict[SIGNATURE_STRING] = self.signature
        return cert_dict

    def parse(self, certificate_file):
        """
        Parse a certificate file and populate the instance's attributes.

        :param str certificate_file: the name of the certificate file.
        """
        cert = load_json_file(certificate_file)
        self.subject = cert[SUBJECT_STRING]
        self.issuer = cert[ISSUER_STRING]
        self.version = cert[VERSION_STRING]
        self.comment = cert[COMMENT_STRING]
        self.can_issue = cert[CAN_ISSUE_STRING]
        self.issuing_time = cert[ISSUING_TIME_STRING]
        self.expiration_time = cert[EXPIRATION_TIME_STRING]
        self.encryption_algorithm = cert[ENC_ALGORITHM_STRING]
        self.subject_enc_key = base64.b64decode(cert[SUBJECT_ENC_KEY_STRING])
        self.sign_algorithm = cert[SIGN_ALGORITHM_STRING]
        self.subject_sig_key = base64.b64decode(cert[SUBJECT_SIG_KEY_STRING])
        self.signature = base64.b64decode(cert[SIGNATURE_STRING])

    @classmethod
    def from_values(cls, subject, issuer, version, comment, can_issue,
                    subject_enc_key, subject_sig_key, iss_priv_key, ):
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
        cert = Certificate()
        cert.subject = subject
        cert.issuer = issuer
        cert.version = version
        cert.comment = comment
        cert.can_issue = can_issue
        cert.issuing_time = int(time.time())
        cert.expiration_time = cert.issuing_time + Certificate.VALIDITY_PERIOD
        cert.encryption_algorithm = Certificate.ENCRYPT_ALGORITHM
        cert.subject_enc_key = subject_enc_key
        cert.sign_algorithm = Certificate.SIGN_ALGORITHM
        cert.subject_sig_key = subject_sig_key
        data_to_sign = cert.__str__(with_signature=False)
        data_to_sign = data_to_sign.encode('utf-8')
        cert.signature = sign(data_to_sign, iss_priv_key)
        return cert

    def __str__(self, with_signature=True):
        cert_dict = copy.deepcopy(self.get_cert_dict(with_signature))
        cert_dict[SUBJECT_SIG_KEY_STRING] = \
            base64.b64encode(cert_dict[SUBJECT_SIG_KEY_STRING]).decode('utf-8')
        cert_dict[SUBJECT_ENC_KEY_STRING] = \
            base64.b64encode(cert_dict[SUBJECT_ENC_KEY_STRING]).decode('utf-8')
        if with_signature:
            cert_dict[SIGNATURE_STRING] = \
                base64.b64encode(cert_dict[SIGNATURE_STRING]).decode('utf-8')
        cert_str = json.dumps(cert_dict, sort_keys=True, indent=4)
        return cert_str

    def __eq__(self, other):  # pragma: no cover
        return str(self) == str(other)
