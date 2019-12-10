# Copyright 2014 ETH Zurich
# Copyright 2018 ETH Zurich, Anapaya Systems
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
:mod:`ca` --- SCION topology ca generator
=============================================
"""
# Stdlib
from collections import defaultdict
import datetime

# External packages
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# SCION
from lib.crypto.util import (
    get_ca_cert_file_path,
    get_ca_private_key_file_path,
)
from topology.common import ArgsTopoConfig


class CAGenArgs(ArgsTopoConfig):
    pass


class CAGenerator(object):
    def __init__(self, args):
        """
        :param CAGenArgs args: Contains the passed command line
        arguments and the topo config.
        """
        self.args = args
        self.ca_key_pairs = {}
        self.ca_certs = defaultdict(dict)
        self.ca_private_key_files = defaultdict(dict)
        self.ca_cert_files = defaultdict(dict)

    def generate(self):
        self._iterate(self._gen_ca_key)
        self._iterate(self._gen_ca)
        self._iterate(self._gen_private_key_files)
        self._iterate(self._gen_cert_files)
        return self.ca_private_key_files, self.ca_cert_files, self.ca_certs

    def _iterate(self, f):
        for ca_name, ca_config in self.args.config["CAs"].items():
            f(ca_name, ca_config)

    def _gen_ca_key(self, ca_name, ca_config):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        self.ca_key_pairs[ca_name] = (private_key, public_key)

    def _gen_ca(self, ca_name, ca_config):
        one_day = datetime.timedelta(1, 0, 0)
        five_years = 5 * 365 * one_day
        
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, ca_config["commonName"]),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, ca_config["commonName"]),
        ]))
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + five_years)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(self.ca_key_pairs[ca_name][1])
        # From RFC5280: Conforming CAs MUST include keyUsage extension in
        # certificates that contain public keys that are used to validate
        # digital signatures on other public key certificates or CRLs.
        # To facilitate certification path construction, subjectKeyIdentifier
        # extension MUST appear in all conforming CA certificates, that is, all
        # certificates including the basic constraints extension where the
        # value of cA is TRUE.
        builder = builder.add_extension(
            # basicConstraints identifies whether subject of certificate is a CA
            # pathLen expresses the number of possible intermediate CA
            # certificates in a path built from an end-entity certificate up
            # to the CA certificate.
            x509.BasicConstraints(ca=True, path_length=1), critical=True,
        )
        builder = builder.add_extension(
            # The keyCertSign bit is asserted when the subject public key is
            # used for verifying signatures on public key certificates.
            x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                         data_encipherment=False, key_agreement= False, key_cert_sign=True,
                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True,
        )
        builder = builder.add_extension(
            # From RFC5280: The keyIdentifier is composed of the 160-bit SHA-1
            # hash of the value of the BIT STRING subjectPublicKey
            x509.SubjectKeyIdentifier.from_public_key(self.ca_key_pairs[ca_name][1]),
            critical=False,
        )
        certificate = builder.sign(
            private_key=self.ca_key_pairs[ca_name][0], algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        self.ca_certs[ca_config["ISD"]][ca_name] = certificate

    def _gen_private_key_files(self, ca_name, ca_config):
        isd = ca_config["ISD"]
        ca_private_key_path = get_ca_private_key_file_path("ISD%s" % isd, ca_name)
        self.ca_private_key_files[isd][ca_private_key_path] = \
            self.ca_key_pairs[ca_name][0].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )

    def _gen_cert_files(self, ca_name, ca_config):
        isd = ca_config["ISD"]
        ca_cert_path = get_ca_cert_file_path("ISD%s" % isd, ca_name)
        self.ca_cert_files[isd][ca_cert_path] = \
            self.ca_certs[ca_config["ISD"]][ca_name].public_bytes(
                serialization.Encoding.PEM
            )
