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

# External packages
from OpenSSL import crypto

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
        self.ca_key_pairs[ca_name] = crypto.PKey()
        self.ca_key_pairs[ca_name].generate_key(crypto.TYPE_RSA, 2048)

    def _gen_ca(self, ca_name, ca_config):
        ca = crypto.X509()
        ca.set_version(3)
        ca.set_serial_number(1)
        ca.get_subject().CN = ca_config["commonName"]
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(self.ca_key_pairs[ca_name])

        # From RFC5280: Conforming CAs MUST include keyUsage extension in
        # certificates that contain public keys that are used to validate
        # digital signatures on other public key certificates or CRLs.
        # To facilitate certification path construction, subjectKeyIdentifier
        # extension MUST appear in all conforming CA certificates, that is, all
        # certificates including the basic constraints extension where the
        # value of cA is TRUE.
        ca.add_extensions([
            # basicConstraints identifies whether subject of certificate is a CA
            # pathLen expresses the number of possible intermediate CA
            # certificates in a path built from an end-entity certificate up
            # to the CA certificate.
            crypto.X509Extension(
                b"basicConstraints", True, b"CA:TRUE, pathlen:1"),
            # The keyCertSign bit is asserted when the subject public key is
            # used for verifying signatures on public key certificates.
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            # From RFC5280: The keyIdentifier is composed of the 160-bit SHA-1
            # hash of the value of the BIT STRING subjectPublicKey
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash",
                                 subject=ca),
        ])
        ca.sign(self.ca_key_pairs[ca_name], "sha256")
        self.ca_certs[ca_config["ISD"]][ca_name] = ca

    def _gen_private_key_files(self, ca_name, ca_config):
        isd = ca_config["ISD"]
        ca_private_key_path = \
            get_ca_private_key_file_path("ISD%s" % isd, ca_name)
        self.ca_private_key_files[isd][ca_private_key_path] = \
            crypto.dump_privatekey(crypto.FILETYPE_PEM,
                                   self.ca_key_pairs[ca_name])

    def _gen_cert_files(self, ca_name, ca_config):
        isd = ca_config["ISD"]
        ca_cert_path = get_ca_cert_file_path("ISD%s" % isd, ca_name)
        self.ca_cert_files[isd][ca_cert_path] = \
            crypto.dump_certificate(crypto.FILETYPE_PEM,
                                    self.ca_certs[ca_config["ISD"]][ca_name])
