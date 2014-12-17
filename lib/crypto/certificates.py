"""
certificates.py

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

from asymcrypto import *
import time
import json
import logging
import os
import base64


def load_root_certificates(path):
    """
    Loads into a dictionary all root certificates. The key is the concatenation
    of the certificate's subject and version (i.e. ISD:11-AD:1-V:0,
    www.abc.com-V:0, scion@ethz.ch-V:0).

    @param path: Parent directory where all root certificate files are stored.
    """
    if not os.path.exists(path):
        logging.info('The given path %s is not valid.', path)
        return {}
    roots = {}
    for root, dirs, files in os.walk(path):
        for name in files:
            if name.endswith((".crt")):
                with open(path + name, "r") as file_handler:
                    cert_raw = file_handler.read()
                cert = Certificate(cert_raw)
                roots[cert.subject + '-V:' + str(cert.version)] = cert
    return roots


class Certificate(object):
    """
    Certificate class.
    """
    VALIDITY_PERIOD = 365 * 24 * 60 * 60
    SIGN_ALGORITHM = 'ed25519'
    ENCRYPT_ALGORITHM = 'curve25519xsalsa20poly1305'

    def __init__(self, raw=None):
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
        if raw:
            self.parse(raw)

    def get_cert_dict(self, with_signature=False):
        """
        Returns a dictionary with the certificate's content.

        @param with_signature: Boolean telling if the signature must also be
            inserted into the certificate.
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

    def parse(self, raw):
        """
        Initializes a certificate object out of a raw certificate.

        @param raw: Raw string produced by packing the certificate.
        """
        try:
            cert = json.loads(raw)
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
    def from_values(cls, subject, sub_pub_key, sub_enc_key, issuer, iss_priv_key, version):
        """
        Generates a certificate storing in it relevant information about
        subject, issuer and validity of the certificate itself.

        @param subject: String containing information about the certificate
            subject. It can either be an AD, an email address or a domain
            address.
        @param sub_pub_key: Base64 string containing the public key of the
            subject.
        @param sub_enc_key: Base64 string containing the encryption key of the
            subject.
        @param issuer: String containing information about the certificate
            issuer. It can only be an AD.
        @param iss_priv_key: Base64 string containing the private key of the
            issuer.
        @param version: Certificate version.
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

    def verify(self, subject, issuer_cert):
        """
        One step verification.

        @param subject: String containing the certificate's subject.
        @param issuer_cert: String containing the certificate of the issuer.
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

    def pack(self):
        """
        Packs the certificate into a string.
        """
        cert_dict = self.get_cert_dict(with_signature=True)
        cert_str = json.dumps(cert_dict, sort_keys=True)
        return cert_str

    def __str__(self):
        cert_str = self.pack()
        cert_str = cert_str.replace('{', '{\n ')
        cert_str = cert_str.replace(', ', ',\n ')
        cert_str = cert_str.replace('}', '\n}')
        return cert_str


class CertificateChain(object):
    """
    CertificateChain class. It is an ordered sequence of certificates, in which:
    the first certificate is the one at the end of a certificate chain and the
    last is the certificate signed by the core ISD. Therefore, starting from the
    first one, each certificate should be verified by the next one in the
    sequence.
    """

    def __init__(self, raw=None):
        self.certs = []
        if raw:
            self.parse(raw)

    def parse(self, raw):
        """
        Initializes a certificate chain object out of a raw certificate chain.

        @param raw: Raw string produced by packing the certificate chain.
        """
        try:
            chain = json.loads(raw)
        except (ValueError, KeyError, TypeError):
            logging.error("Certificate Chain: JSON format error.")
            return
        for index in range(0, len(chain)):
            cert_raw = json.dumps(chain[str(index)], sort_keys=True)
            self.certs.append(Certificate(cert_raw))

    @classmethod
    def from_values(cls, cert_list):
        """
        Builds a new certificate chain, given a list of certificates.

        @param cert_list: List of certificates to insert into the chain.
        """
        cert_chain = CertificateChain()
        cert_chain.certs = cert_list
        return cert_chain

    def verify(self, subject, roots, root_cert_version):
        """
        Entire chain verification. It verifies each pair and at the end
        verifies the last certificate of the certificate chain with the
        corresponding root certificate.

        @param subject: String containing the subject of the first certificate
            in the certificate chain.
        @param roots: Dictionary containing the root certificates.
        @param root_cert_version: Version of the root certificate which signed
            the last certificate in the certificate chain.
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

    def pack(self):
        """
        Packs the certificate chain into a string.
        """
        chain_dict = {}
        for index, cert in self.certs:
            cert_dict = cert.get_cert_dict(with_signature=True)
            chain_dict[index] = cert_dict
        chain_str = json.dumps(chain_dict, sort_keys=True)
        return chain_str

    def __str__(self):
        cert_list = []
        for cert in self.certs:
            cert_list.append(str(cert))
        chain_str = '\n'.join(cert_list)
        return chain_str
