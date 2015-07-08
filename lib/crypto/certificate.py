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
from lib.crypto.nacl import crypto_sign_ed25519_open
from lib.crypto.asymcrypto import sign, verify


def verify_sig_chain_trc(msg, sig, subject, chain, trc, trc_version):
    """
    Verify whether the packed message with attached signature is validly
    signed by a particular subject belonging to a valid certificate chain.

    :param msg: message corresponding to the given signature.
    :type msg: str
    :param sig: signature computed on msg.
    :type sig: bytes
    :param subject: signer identity.
    :type subject: str
    :param chain: Certificate chain containing the signing entity's certificate.
    :type chain: :class:`CertificateChain`
    :param trc: TRC containing all root of trust certificates for one ISD.
    :type trc: :class:`TRC`
    :param trc_version: TRC version.
    :type trc_version: int

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
        if subject not in trc.core_ads:
            logging.warning('Signer\'s public key has not been found.')
            return False
        verifying_key = trc.core_ads[subject].subject_sig_key
    return verify(msg, sig, verifying_key)


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
    :ivar subject_sig_key: the public key of the subject.
    :type subject_sig_key: bytes
    :ivar subject_enc_key: the public part of the encryption key.
    :type subject_enc_key: bytes
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
    :type signature: bytes
    """
    VALIDITY_PERIOD = 365 * 24 * 60 * 60
    SIGN_ALGORITHM = 'ed25519'
    ENCRYPT_ALGORITHM = 'curve25519xsalsa20poly1305'

    def __init__(self, certificate_file=None):
        """
        Initialize an instance of the class Certificate.

        :param certificate_file: the name of the certificate file.
        :type certificate_file: str
        """
        self.subject = ''
        self.subject_sig_key = b''
        self.subject_enc_key = b''
        self.issuer = ''
        self.version = 0
        self.issuing_time = 0
        self.expiration_time = 0
        self.sign_algorithm = ''
        self.encryption_algorithm = ''
        self.signature = b''
        if certificate_file:
            self.parse(certificate_file)

    def get_cert_dict(self, with_signature):
        """
        Return the certificate information.

        :param with_signature: tells whether the signature must also be
                               included in the returned data.
        :type with_signature: bool

        :returns: the certificate information.
        :rtype: dict
        """
        cert_dict = {'subject': self.subject,
                     'subject_sig_key': self.subject_sig_key,
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
        self.subject_sig_key = base64.b64decode(cert['subject_sig_key'])
        self.subject_enc_key = base64.b64decode(cert['subject_enc_key'])
        self.issuer = cert['issuer']
        self.version = cert['version']
        self.issuing_time = cert['issuing_time']
        self.expiration_time = cert['expiration_time']
        self.sign_algorithm = cert['sign_algorithm']
        self.encryption_algorithm = cert['enc_algorithm']
        self.signature = base64.b64decode(cert['signature'])

    @classmethod
    def from_values(cls, subject, subject_sig_key, subject_enc_key, issuer,
                    iss_priv_key, version):
        """
        Generate a Certificate instance.

        :param subject: the certificate subject. It can either be an AD, an
                        email address or a domain address.
        :type subject: str
        :param subject_sig_key: the public key of the subject.
        :type subject_sig_key: bytes
        :param subject_enc_key: the public part of the encryption key.
        :type subject_enc_key: bytes
        :param issuer: the certificate issuer. It can only be an AD.
        :type issuer: str
        :param iss_priv_key: the issuer's private key. It is used to sign the
                             certificate.
        :type iss_priv_key: bytes
        :param version: the certificate version.
        :type version: int

        :returns: the newly created Certificate instance.
        :rtype: :class:`Certificate`
        """
        cert = Certificate()
        cert.subject = subject
        cert.subject_sig_key = subject_sig_key
        cert.subject_enc_key = subject_enc_key
        cert.issuer = issuer
        cert.version = version
        cert.issuing_time = int(time.time())
        cert.expiration_time = cert.issuing_time + Certificate.VALIDITY_PERIOD
        cert.sign_algorithm = Certificate.SIGN_ALGORITHM
        cert.encryption_algorithm = Certificate.ENCRYPT_ALGORITHM
        data_to_sign = cert.__str__(with_signature=False)
        data_to_sign = data_to_sign.encode('utf-8')
        cert.signature = sign(data_to_sign, iss_priv_key)
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
        cert.subject_sig_key = cert_dict['subject_sig_key']
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
        data_to_verify = self.__str__(with_signature=False).encode('utf-8')
        msg_with_sig = self.signature + data_to_verify
        try:
            crypto_sign_ed25519_open(msg_with_sig, issuer_cert.subject_sig_key)
            return True
        except:
            logging.warning("The certificate is not valid.")
            return False

    def __str__(self, with_signature=True):
        """
        Convert the instance in a readable format.

        :param with_signature:
        :type with_signature:

        :returns: the certificate information.
        :rtype: str
        """
        cert_dict = copy.deepcopy(self.get_cert_dict(with_signature))
        cert_dict['subject_sig_key'] = \
            base64.b64encode(cert_dict['subject_sig_key']).decode('utf-8')
        cert_dict['subject_enc_key'] = \
            base64.b64encode(cert_dict['subject_enc_key']).decode('utf-8')
        if with_signature:
            cert_dict['signature'] = \
                base64.b64encode(cert_dict['signature']).decode('utf-8')
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
            cert_dict = chain[str(index)]
            cert_dict['subject_sig_key'] = \
                base64.b64decode(cert_dict['subject_sig_key'])
            cert_dict['subject_enc_key'] = \
                base64.b64decode(cert_dict['subject_enc_key'])
            cert_dict['signature'] = \
                base64.b64decode(cert_dict['signature'])
            cert = Certificate.from_dict(cert_dict)
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

    def verify(self, subject, trc, trc_version):
        """
        Perform the entire chain verification. It verifies each pair and at the
        end verifies the last certificate of the chain with the root certificate
        that was used to sign it.

        :param subject: the subject of the first certificate in the certificate
                        chain.
        :type subject: str
        :param trc: TRC containing all root of trust certificates for one ISD.
        :type trc: :class:`TRC`
        :param trc_version: TRC version.
        :type trc_version: int

        :returns: True or False whether the verification succeeds or fails.
        :rtype: bool
        """
        if subject in trc.core_ads:
            return True
        if len(self.certs) == 0:
            logging.warning("The certificate chain is not initialized.")
            return False
        if trc.version != trc_version:
            logging.warning("The TRC version is incorrect.")
            return False
        cert = self.certs[0]
        for issuer_cert in self.certs[1:]:
            if not cert.verify(subject, issuer_cert):
                return False
            cert = issuer_cert
            subject = cert.subject
        if cert.issuer not in trc.core_ads:
            logging.warning("The verification against the TRC failed.")
            return False
        if not cert.verify(subject, trc.core_ads[cert.issuer]):
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
            cert_dict = copy.deepcopy(cert.get_cert_dict(True))
            cert_dict['subject_sig_key'] = \
                base64.b64encode(cert_dict['subject_sig_key']).decode('utf-8')
            cert_dict['subject_enc_key'] = \
                base64.b64encode(cert_dict['subject_enc_key']).decode('utf-8')
            cert_dict['signature'] = \
                base64.b64encode(cert_dict['signature']).decode('utf-8')
            chain_dict[index] = cert_dict
            index += 1
        chain_str = json.dumps(chain_dict, sort_keys=True, indent=4)
        return chain_str


class TRC(object):
    """
    The TRC class parses the TRC file of an ISD and stores such
    information for further use.

    :ivar isd_id: the ISD identifier.
    :type isd_id: int
    :ivar version: the TRC file version.
    :type version: int
    :ivar time: the TRC file creation timestamp.
    :type time: int
    :ivar core_quorum: number of trust roots necessary to sign a new TRC.
    :type core_quorum: int
    :ivar trc_quorum: number of trust roots necessary to sign a new ISD
                      cross-signing certificate.
    :type trc_quorum: int
    :ivar core_isps: the set of core ISPs and their certificates.
    :type core_isps: dict
    :ivar root_cas: the set of root CAs and their certificates.
    :type root_cas: dict
    :ivar core_ads: the set of core ADs and their certificates.
    :type core_ads: dict
    :ivar policies: additional management policies for the ISD.
    :type policies: dict
    :ivar registry_server_addr: the root registry server's address.
    :type registry_server_addr: str
    :ivar registry_server_cert: the root registry server's certificate.
    :type registry_server_cert: str
    :ivar root_dns_server_addr: the root DNS server's address.
    :type root_dns_server_addr: str
    :ivar root_dns_server_cert: the root DNS server's certificate.
    :type root_dns_server_cert: str
    :ivar trc_server_addr: the TRC server's address.
    :type trc_server_addr: str
    :ivar signatures: signatures generated by a quorum of trust roots.
    :type signatures: dict
    """

    def __init__(self, trc_file=None):
        """
        Initialize an instance of the class TRC.

        :param trc_file: the name of the TRC file.
        :type trc_file: str
        """
        self.isd_id = 0
        self.version = 0
        self.time = 0
        self.core_quorum = 0
        self.trc_quorum = 0
        self.core_isps = {}
        self.root_cas = {}
        self.core_ads = {}
        self.policies = {}
        self.registry_server_addr = ''
        self.registry_server_cert = ''
        self.root_dns_server_addr = ''
        self.root_dns_server_cert = ''
        self.trc_server_addr = ''
        self.signatures = {}
        if trc_file:
            self.parse(trc_file)

    def get_trc_dict(self, with_signatures):
        """
        Return the TRC information.

        :param with_signatures: True or False whether the returned data should
                                contain the signatures section or not.
        :type with_signatures: bool

        :returns: the TRC information.
        :rtype: dict
        """
        trc_dict = {
            'isd_id': self.isd_id,
            'version': self.version,
            'time': self.time,
            'core_quorum': self.core_quorum,
            'trc_quorum': self.trc_quorum,
            'core_isps': self.core_isps,
            'root_cas': self.root_cas,
            'core_ads': self.core_ads,
            'policies': self.policies,
            'registry_server_addr': self.registry_server_addr,
            'registry_server_cert': self.registry_server_cert,
            'root_dns_server_addr': self.root_dns_server_addr,
            'root_dns_server_cert': self.root_dns_server_cert,
            'trc_server_addr': self.trc_server_addr}
        if with_signatures:
            trc_dict['signatures'] = self.signatures
        return trc_dict

    def parse(self, trc_file):
        """
        Parse a TRC file and populate the instance's attributes.

        :param trc_file: the name of the TRC file.
        :type trc_file: str
        """
        try:
            with open(trc_file) as trc_fh:
                trc = json.load(trc_fh)
        except (ValueError, KeyError, TypeError):
            logging.error("TRC: JSON format error.")
            return
        self.isd_id = trc['isd_id']
        self.version = trc['version']
        self.time = trc['time']
        self.core_quorum = trc['core_quorum']
        self.trc_quorum = trc['trc_quorum']
        self.core_isps = trc['core_isps']
        self.root_cas = trc['root_cas']
        for subject in trc['core_ads']:
            cert_dict = \
                base64.b64decode(trc['core_ads'][subject]).decode('utf-8')
            cert_dict = json.loads(cert_dict)
            cert_dict['subject_sig_key'] = \
                base64.b64decode(cert_dict['subject_sig_key'])
            cert_dict['subject_enc_key'] = \
                base64.b64decode(cert_dict['subject_enc_key'])
            cert_dict['signature'] = \
                base64.b64decode(cert_dict['signature'])
            self.core_ads[subject] = Certificate.from_dict(cert_dict)
        self.policies = trc['policies']
        self.registry_server_addr = trc['registry_server_addr']
        self.registry_server_cert = trc['registry_server_cert']
        self.root_dns_server_addr = trc['root_dns_server_addr']
        self.root_dns_server_cert = trc['root_dns_server_cert']
        self.trc_server_addr = trc['trc_server_addr']
        for subject in trc['signatures']:
            self.signatures[subject] = \
                base64.b64decode(trc['signatures'][subject])

    @classmethod
    def from_values(cls, isd_id, version, core_quorum, trc_quorum, core_isps,
                    root_cas, core_ads, policies, registry_server_addr,
                    registry_server_cert, root_dns_server_addr,
                    root_dns_server_cert, trc_server_addr, signatures):
        """
        Generate a TRC instance.

        :param isd_id: the ISD identifier.
        :type isd_id: int
        :param version: the TRC file version.
        :type version: int
        :param core_quorum: number of trust roots necessary to sign a new TRC.
        :type core_quorum: int
        :param trc_quorum: number of trust roots necessary to sign a new ISD
                           cross-signing certificate.
        :type trc_quorum: int
        :param core_isps: the set of core ISPs and their certificates.
        :type core_isps: dict
        :param root_cas: the set of root CAs and their certificates.
        :type root_cas: dict
        :param core_ads: the set of core ADs and their certificates.
        :type core_ads: dict
        :param policies: additional management policies for the ISD.
        :type policies: dict
        :param registry_server_addr: the root registry server's address.
        :type registry_server_addr: str
        :param registry_server_cert: the root registry server's certificate.
        :type registry_server_cert: str
        :param root_dns_server_addr: the root DNS server's address.
        :type root_dns_server_addr: str
        :param root_dns_server_cert: the root DNS server's certificate.
        :type root_dns_server_cert: str
        :param trc_server_addr: the TRC server's address.
        :type trc_server_addr: str
        :param signatures: signatures generated by a quorum of trust roots.
        :type signatures: dict

        :returns: the newly created TRC instance.
        :rtype: :class:`TRC`
        """
        trc = TRC()
        trc.isd_id = isd_id
        trc.version = version
        trc.time = int(time.time())
        trc.core_quorum = core_quorum
        trc.trc_quorum = trc_quorum
        trc.core_isps = core_isps
        trc.root_cas = root_cas
        trc.core_ads = core_ads
        trc.policies = policies
        trc.registry_server_addr = registry_server_addr
        trc.registry_server_cert = registry_server_cert
        trc.root_dns_server_addr = root_dns_server_addr
        trc.root_dns_server_cert = root_dns_server_cert
        trc.trc_server_addr = trc_server_addr
        trc.signatures = signatures
        return trc

    def verify(self):
        """
        Perform signatures verification.

        :returns: True or False whether the verification succeeds or fails.
        :rtype: bool
        """
        data_to_verify = self.__str__(with_signatures=False).encode('utf-8')
        for signer in self.signatures:
            if signer not in self.core_ads:
                logging.warning("A signature could not be verified.")
                return False
            public_key = self.core_ads[signer].subject_sig_key
            msg_with_sig = self.signatures[signer] + data_to_verify
            try:
                crypto_sign_ed25519_open(msg_with_sig, public_key)
            except:
                logging.warning("A signature is not valid.")
                return False
        return True

    def __str__(self, with_signatures=True):
        """
        Convert the instance in a readable format.

        :param with_signatures:
        :type with_signatures:

        :returns: the TRC information.
        :rtype: str
        """
        trc_dict = copy.deepcopy(self.get_trc_dict(with_signatures))
        for subject in trc_dict['core_ads']:
            cert_str = str(trc_dict['core_ads'][subject])
            trc_dict['core_ads'][subject] = \
                base64.b64encode(cert_str.encode('utf-8')).decode('utf-8')
        if with_signatures:
            for subject in trc_dict['signatures']:
                signature = trc_dict['signatures'][subject]
                trc_dict['signatures'][subject] = \
                    base64.b64encode(signature).decode('utf-8')
        trc_str = json.dumps(trc_dict, sort_keys=True, indent=4)
        return trc_str
