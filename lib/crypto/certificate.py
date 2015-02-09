# Copyright 2014 ETH Zurich

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`certificate` --- SCION certificate parser
===========================================
"""

from lib.crypto.asymcrypto import *
import time
import json
import logging
import os
import base64


def load_root_certificates(path):
    """
    Load all root certificates into a dictionary. The key is the concatenation
    of the certificate's subject and version (i.e. ISD:11-AD:1-V:0,
    www.abc.com-V:0, scion@ethz.ch-V:0).

    :param path: parent directory where all root certificate files are stored.
    :type path: str
    :returns: a set of root certificates.
    :rtype: dict
    """
    if not os.path.exists(path):
        logging.info('The given path %s is not valid.', path)
        return {}
    roots = {}
    for root, dirs, files in os.walk(path):
        for name in files:
            if name.endswith((".crt")):
                cert = Certificate(path + name)
                roots[cert.subject + '-V:' + str(cert.version)] = cert
    return roots


class Certificate(object):
    """
    The Certificate class parses a certificate of an AD and stores such
    information for further use.

    :cvar VALIDITY_PERIOD: default validity period (in real seconds) of a new
                           certificate.
    :type VALIDITY_PERIOD: int
    :cvar SIGN_ALGORITHM: default algorithm used to sign a certificate.
    :type SIGN_ALGORITHM: str
    :cvar ENCRYPT_ALGORITHM: default algorithm used to encrypt messages.
    :type ENCRYPT_ALGORITHM: str
    :ivar subject: the certificate subject. It can either be an AD, an email
                   address or a domain address.
    :type subject: str
    :ivar subject_pub_key: the public key of the subject.
    :type subject_pub_key: str
    :ivar subject_enc_key: the public part of the encryption key.
    :type subject_enc_key: str
    :ivar issuer: the certificate issuer. It can only be an AD.
    :type issuer: str
    :ivar version: the certificate version.
    :type version: int
    :ivar issuing_time: the time at which the certificate was created.
    :type issuing_time: int
    :ivar expiration_time: the time at which the certificate expires.
    :type expiration_time: int
    :ivar sign_algorithm: the algorithm used to sign the certificate.
    :type sign_algorithm: str
    :ivar encryption_algorithm: the algorithm used to encrypt messages.
    :type encryption_algorithm: str
    :ivar signature: the certificate signature. It is computed over the rest of
                     the certificate.
    :type signature: str
    """
    VALIDITY_PERIOD = 365 * 24 * 60 * 60
    SIGN_ALGORITHM = 'ed25519'
    ENCRYPT_ALGORITHM = 'curve25519xsalsa20poly1305'

    def __init__(self, certificate_file=None):
        """
        Initialize an instance of the class Certificate.

        :param certificate_file: the name of the certificate file.
        :type certificate_file: str
        :returns: the newly created Certificate instance.
        :rtype: :class:`Certificate`
        """
        self.subject = ''
        self.subject_pub_key = ''
        self.subject_enc_key = ''
        self.issuer = ''
        self.version = 0
        self.issuing_time = 0
        self.expiration_time = 0
        self.sign_algorithm = ''
        self.encryption_algorithm = ''
        self.signature = ''
        if certificate_file:
            self.parse(certificate_file)

    def get_cert_dict(self, with_signature=False):
        """
        Return the certificate information.

        :param with_signature: tells whether the signature must also be
                               included in the returned data.
        :type with_signature: bool
        :returns: the certificate information.
        :rtype: dict
        """
        cert_dict = {'subject': self.subject,
                     'subject_pub_key': self.subject_pub_key,
                     'subject_enc_key': self.subject_enc_key,
                     'issuer': self.issuer,
                     'version': self.version,
                     'issuing_time': self.issuing_time,
                     'expiration_time': self.expiration_time,
                     'sign_algorithm': self.sign_algorithm,
                     'enc_algorithm': self.encryption_algorithm}
        if with_signature:
            cert_dict['signature'] = self.signature
        return cert_dict

    def parse(self, certificate_file):
        """
        Parse a certificate file and populate the instance's attributes.

        :param certificate_file: the name of the certificate file.
        :type certificate_file: str
        """
        try:
            with open(certificate_file) as cert_fh:
                cert = json.load(cert_fh)
        except (ValueError, KeyError, TypeError):
            logging.error("Certificate: JSON format error.")
            return
        self.subject = cert['subject']
        self.subject_pub_key = cert['subject_pub_key']
        self.subject_enc_key = cert['subject_enc_key']
        self.issuer = cert['issuer']
        self.version = cert['version']
        self.issuing_time = cert['issuing_time']
        self.expiration_time = cert['expiration_time']
        self.sign_algorithm = cert['sign_algorithm']
        self.encryption_algorithm = cert['enc_algorithm']
        self.signature = cert['signature']

    @classmethod
    def from_values(cls, subject, sub_pub_key, sub_enc_key, issuer,
        iss_priv_key, version):
        """
        Generate a Certificate instance.

        :param subject: the certificate subject. It can either be an AD, an
                        email address or a domain address.
        :type subject: str
        :param sub_pub_key: the public key of the subject.
        :type sub_pub_key: str
        :param sub_enc_key: the public part of the encryption key.
        :type sub_enc_key: str
        :param issuer: the certificate issuer. It can only be an AD.
        :type issuer: str
        :param iss_priv_key: the issuer's private key. It is used to sign the
                             certificate.
        :type iss_priv_key: str
        :param version: the certificate version.
        :type version: int
        :returns: the newly created Certificate instance.
        :rtype: :class:`Certificate`
        """
        cert = Certificate()
        cert.subject = subject
        cert.subject_pub_key = sub_pub_key
        cert.subject_enc_key = sub_enc_key
        cert.issuer = issuer
        cert.version = version
        cert.issuing_time = int(time.time())
        cert.expiration_time = cert.issuing_time + Certificate.VALIDITY_PERIOD
        cert.sign_algorithm = Certificate.SIGN_ALGORITHM
        cert.encryption_algorithm = Certificate.ENCRYPT_ALGORITHM
        cert_dict = cert.get_cert_dict()
        cert_str = json.dumps(cert_dict, sort_keys=True)
        cert_str = str.encode(cert_str)
        signing_key = base64.b64decode(iss_priv_key)
        cert.signature = base64.standard_b64encode(crypto_sign_ed25519(cert_str,
            signing_key)).decode('ascii')
        return cert

    @classmethod
    def from_dict(cls, cert_dict):
        """
        Generate a Certificate instance.

        :param cert_dict: dictionary containing the certificate information.
        :type cert_dict: dict
        :returns: the newly created Certificate instance.
        :rtype: :class:`Certificate`
        """
        cert = Certificate()
        cert.subject = cert_dict['subject']
        cert.subject_pub_key = cert_dict['subject_pub_key']
        cert.subject_enc_key = cert_dict['subject_enc_key']
        cert.issuer = cert_dict['issuer']
        cert.version = cert_dict['version']
        cert.issuing_time = cert_dict['issuing_time']
        cert.expiration_time = cert_dict['expiration_time']
        cert.sign_algorithm = cert_dict['sign_algorithm']
        cert.encryption_algorithm = cert_dict['enc_algorithm']
        cert.signature = cert_dict['signature']
        return cert

    def verify(self, subject, issuer_cert):
        """
        Perform one step verification.

        :param subject: the certificate subject. It can either be an AD, an
                        email address or a domain address.
        :type subject: str
        :param issuer_cert: the certificate issuer. It can only be an AD.
        :type issuer_cert: str
        :returns: True or False whether the verification succeeds or fails.
        :rtype: bool
        """
        if int(time.time()) >= self.expiration_time:
            logging.warning("The certificate is expired.")
            return False
        if subject != self.subject:
            logging.warning("The given subject doesn't match the " +
                            "certificate's subject")
            return False
        iss_pub_key = issuer_cert.subject_pub_key
        verifyng_key = base64.b64decode(iss_pub_key)
        cert_dict = self.get_cert_dict()
        cert_str = json.dumps(cert_dict, sort_keys=True)
        cert_str = str.encode(cert_str)
        try:
            crypto_sign_ed25519_open(base64.b64decode(self.signature),
                verifyng_key)
            return True
        except:
            logging.warning("The certificate is not valid.")
            return False

    def __str__(self):
        """
        Convert the instance in a readable format.

        :returns: the certificate information.
        :rtype: str
        """
        cert_dict = self.get_cert_dict(with_signature=True)
        cert_str = json.dumps(cert_dict, sort_keys=True, indent=4)
        return cert_str


class CertificateChain(object):
    """
    The CertificateChain class contains an ordered sequence of certificates, in
    which: the first certificate is the one at the end of a certificate chain
    and the last is the certificate signed by the core ISD. Therefore, starting
    from the first one, each certificate should be verified by the next one in
    the sequence.

    :ivar certs: (ordered) certificates forming the chain.
    :type certs: list
    """

    def __init__(self, chain_file=None):
        """
        Initialize an instance of the class CertificateChain.

        :param chain_file: the name of the certificate chain file.
        :type chain_file: str
        :returns: the newly created CertificateChain instance.
        :rtype: :class:`CertificateChain`
        """
        self.certs = []
        if chain_file:
            self.parse(chain_file)

    def parse(self, chain_file):
        """
        Parse a certificate chain file and populate the instance's attributes.

        :param chain_file: the name of the certificate chain file.
        :type chain_file: str
        """
        try:
            with open(chain_file) as chain_fh:
                chain = json.load(chain_fh)
        except (ValueError, KeyError, TypeError):
            logging.error("Certificate Chain: JSON format error.")
            return
        for index in range(1, len(chain) + 1):
            cert = Certificate.from_dict(chain[str(index)])
            self.certs.append(cert)

    @classmethod
    def from_values(cls, cert_list):
        """
        Generate a CertificateChain instance.

        :param cert_list: (ordered) certificates to populate the chain with.
        :type cert_list: list
        :returns: the newly created CertificateChain instance.
        :rtype: :class:`CertificateChain`
        """
        cert_chain = CertificateChain()
        cert_chain.certs = cert_list
        return cert_chain

    def verify(self, subject, roots, root_cert_version):
        """
        Perform the entire chain verification. It verifies each pair and at the
        end verifies the last certificate of the chain with the root certificate
        that was used to sign it.

        :param subject: the subject of the first certificate in the certificate
                        chain.
        :type subject: str
        :param roots: the root certificates.
        :type roots: dict
        :param root_cert_version: the version of the root certificate.
        :type root_cert_version: int
        :returns: True or False whether the verification succeeds or fails.
        :rtype: bool
        """
        if len(self.certs) == 0:
            logging.warning("The certificate chain is not initialized.")
            return False
        cert = self.certs[0]
        for issuer_cert in self.certs[1:]:
            if not cert.verify(subject, issuer_cert):
                return False
            cert = issuer_cert
            subject = cert.subject
        root_key = cert.issuer + '-V:' + str(root_cert_version)
        if root_key not in roots.keys():
            logging.warning("Issuer public key not found.")
            return False
        if not cert.verify(subject, roots[root_key]):
            return False
        return True

    def __str__(self):
        """
        Convert the instance in a readable format.

        :returns: the CertificateChain information.
        :rtype: str
        """
        chain_dict = {}
        index = 1
        for cert in self.certs:
            chain_dict[index] = cert.get_cert_dict(with_signature=True)
            index += 1
        chain_str = json.dumps(chain_dict, sort_keys=True, indent=4)
        return chain_str
