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
from lib.packet.scion_addr import ISD_AS
from lib.util import load_json_file


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


class Certificate(object):
    """
    The Certificate class parses a certificate of an AS and stores such
    information for further use.

    :cvar int VALIDITY_PERIOD:
        default validity period (in real seconds) of a new certificate.
    :cvar str SIGN_ALGORITHM: default algorithm used to sign a certificate.
    :cvar str ENCRYPT_ALGORITHM: default algorithm used to encrypt messages.
    :ivar str subject:
        the certificate subject. It can either be an AS, an email address or a
        domain address.
    :ivar bytes subject_sig_key: the public key of the subject.
    :ivar bytes subject_enc_key: the public part of the encryption key.
    :ivar str issuer: the certificate issuer. It can only be an AS.
    :ivar int version: the certificate version.
    :ivar int issuing_time: the time at which the certificate was created.
    :ivar int expiration_time: the time at which the certificate expires.
    :ivar str sign_algorithm: the algorithm used to sign the certificate.
    :ivar str encryption_algorithm: the algorithm used to encrypt messages.
    :ivar bytes signature:
        the certificate signature. It is computed over the rest of the
        certificate.
    """
    VALIDITY_PERIOD = 365 * 24 * 60 * 60
    SIGN_ALGORITHM = 'ed25519'
    ENCRYPT_ALGORITHM = 'curve25519xsalsa20poly1305'

    def __init__(self, certificate_file=None):
        """
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

        :param bool with_signature:
            tells whether the signature must also be included in the returned
            data.
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

        :param str certificate_file: the name of the certificate file.
        """
        cert = load_json_file(certificate_file)
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

        :param dict cert_dict:
            dictionary containing the certificate information.
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

        :param str subject:
            the certificate subject. It can either be an AS, an email address or
            a domain address.
        :param str issuer_cert: the certificate issuer. It can only be an AS.
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
        msg = self.__str__(with_signature=False).encode('utf-8')
        return verify(msg, self.signature, issuer_cert.subject_sig_key)

    def __str__(self, with_signature=True):
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

    :ivar list certs: (ordered) certificates forming the chain.
    """

    def __init__(self, chain_raw=None):
        """
        :param str chain_raw: certificate chain as json string.
        """
        self.certs = []
        if chain_raw:
            self.parse(chain_raw)

    def parse(self, chain_raw):
        """
        Parse a certificate chain file and populate the instance's attributes.

        :param str chain_raw: certificate chain as json string.
        """
        chain = json.loads(chain_raw)
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

        :param list cert_list:
            (ordered) certificates to populate the chain with.
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

        :param str subject:
            the subject of the first certificate in the certificate chain.
        :param trc: TRC containing all root of trust certificates for one ISD.
        :type trc: :class:`TRC`
        :param int trc_version: TRC version.
        :returns: True or False whether the verification succeeds or fails.
        :rtype: bool
        """
        if subject in trc.core_ases:
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
        if cert.issuer not in trc.core_ases:
            logging.warning("The verification against the TRC failed.")
            return False
        if not cert.verify(subject, trc.core_ases[cert.issuer]):
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
        Convert the instance to json format.

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

    def pack(self):
        return self.to_json().encode('utf-8')

    def __str__(self):
        return self.to_json()


class TRC(object):
    """
    The TRC class parses the TRC file of an ISD and stores such
    information for further use.

    :ivar int isd: the ISD identifier.
    :ivar int version: the TRC file version.
    :ivar int time: the TRC file creation timestamp.
    :ivar int core_quorum: number of trust roots necessary to sign a new TRC.
    :ivar int trc_quorum:
        number of trust roots necessary to sign a new ISD cross-signing
        certificate.
    :ivar dict core_isps: the set of core ISPs and their certificates.
    :ivar dict root_cas: the set of root CAs and their certificates.
    :ivar dict core_ases: the set of core ASes and their certificates.
    :ivar dict policies: additional management policies for the ISD.
    :ivar str registry_server_addr: the root registry server's address.
    :ivar str registry_server_cert: the root registry server's certificate.
    :ivar str root_dns_server_addr: the root DNS server's address.
    :ivar str root_dns_server_cert: the root DNS server's certificate.
    :ivar str trc_server_addr: the TRC server's address.
    :ivar dict signatures: signatures generated by a quorum of trust roots.
    """

    def __init__(self, trc_raw=None):
        """
        :param str trc_raw: TRC as json string.
        """
        self.isd = 0
        self.version = 0
        self.time = 0
        self.core_quorum = 0
        self.trc_quorum = 0
        self.core_isps = {}
        self.root_cas = {}
        self.core_ases = {}
        self.policies = {}
        self.registry_server_addr = ''
        self.registry_server_cert = ''
        self.root_dns_server_addr = ''
        self.root_dns_server_cert = ''
        self.trc_server_addr = ''
        self.signatures = {}
        if trc_raw:
            self.parse(trc_raw)

    def get_isd_ver(self):
        return self.isd, self.version

    def get_core_ases(self):
        res = []
        for key in self.core_ases:
            res.append(ISD_AS(key))
        return res

    def get_trc_dict(self, with_signatures):
        """
        Return the TRC information.

        :param bool with_signatures:
            If True, include signatures in the return value.
        :returns: the TRC information.
        :rtype: dict
        """
        trc_dict = {
            'isd': self.isd,
            'version': self.version,
            'time': self.time,
            'core_quorum': self.core_quorum,
            'trc_quorum': self.trc_quorum,
            'core_isps': self.core_isps,
            'root_cas': self.root_cas,
            'core_ases': self.core_ases,
            'policies': self.policies,
            'registry_server_addr': self.registry_server_addr,
            'registry_server_cert': self.registry_server_cert,
            'root_dns_server_addr': self.root_dns_server_addr,
            'root_dns_server_cert': self.root_dns_server_cert,
            'trc_server_addr': self.trc_server_addr}
        if with_signatures:
            trc_dict['signatures'] = self.signatures
        return trc_dict

    def parse(self, trc_raw):
        """
        Parse a TRC file and populate the instance's attributes.

        :param str trc_raw: TRC as json string.
        """
        trc = json.loads(trc_raw)
        self.isd = trc['isd']
        self.version = trc['version']
        self.time = trc['time']
        self.core_quorum = trc['core_quorum']
        self.trc_quorum = trc['trc_quorum']
        self.core_isps = trc['core_isps']
        self.root_cas = trc['root_cas']
        for subject in trc['core_ases']:
            cert_dict = base64.b64decode(
                trc['core_ases'][subject]).decode('utf-8')
            cert_dict = json.loads(cert_dict)
            cert_dict['subject_sig_key'] = base64.b64decode(
                cert_dict['subject_sig_key'])
            cert_dict['subject_enc_key'] = base64.b64decode(
                cert_dict['subject_enc_key'])
            cert_dict['signature'] = base64.b64decode(cert_dict['signature'])
            self.core_ases[subject] = Certificate.from_dict(cert_dict)
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
    def from_values(cls, isd, version, core_quorum, trc_quorum, core_isps,
                    root_cas, core_ases, policies, registry_server_addr,
                    registry_server_cert, root_dns_server_addr,
                    root_dns_server_cert, trc_server_addr, signatures):
        """
        Generate a TRC instance.
        """
        trc = TRC()
        trc.isd = isd
        trc.version = version
        trc.time = int(time.time())
        trc.core_quorum = core_quorum
        trc.trc_quorum = trc_quorum
        trc.core_isps = core_isps
        trc.root_cas = root_cas
        trc.core_ases = core_ases
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
        msg = self.to_json(with_signatures=False).encode('utf-8')
        for signer in self.signatures:
            if signer not in self.core_ases:
                logging.warning("A signature could not be verified.")
                return False
            public_key = self.core_ases[signer].subject_sig_key
            if not verify(msg, self.signatures[signer], public_key):
                logging.warning("A signature is not valid.")
                return False
        return True

    def to_json(self, with_signatures=True):
        """
        Convert the instance to json format.
        """
        trc_dict = copy.deepcopy(self.get_trc_dict(with_signatures))
        for subject in trc_dict['core_ases']:
            cert_str = str(trc_dict['core_ases'][subject])
            trc_dict['core_ases'][subject] = base64.b64encode(
                cert_str.encode('utf-8')).decode('utf-8')
        if with_signatures:
            for subject in trc_dict['signatures']:
                signature = trc_dict['signatures'][subject]
                trc_dict['signatures'][subject] = base64.b64encode(
                    signature).decode('utf-8')
        trc_str = json.dumps(trc_dict, sort_keys=True, indent=4)
        return trc_str

    def pack(self):
        return self.to_json().encode('utf-8')

    def __str__(self):
        return self.to_json()
