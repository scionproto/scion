"""
trcs.py

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

from lib.crypto.asymcrypto import *
import time
import json
import logging
import os
import base64


class TRC(object):
    """
    TRC class.
    """
    SIGN_ALGORITHM = 'ed25519'
    ENCRYPT_ALGORITHM = 'curve25519xsalsa20poly1305'

    def __init__(self, raw=None):
        self.isd_id = ''
        self.version = 0
        self.time = 0
        self.core_isps = ''
        self.registry_key = ''
        self.path_key = ''
        self.root_cas = ''
        self.root_dns_key = ''
        self.root_dns_addr = ''
        self.trc_server = ''
        self.quorum = 0
        self.trc_quorum = 0
        self.policies = ''
        self.signatures = ''
        self.sig_algorithm = ''
        self.enc_algorithm = ''
        if raw:
            self.parse(raw)

    def get_trc_dict(self):
        """
        Returns a dictionary with the TRC's content.
        """
        trc_dict = {
            'isd_id': self.isd_id,
            'version': self.version,
            'time': self.time,
            'core_isps': self.core_isps,
            'registry_key': self.registry_key,
            'path_key': self.path_key,
            'root_cas': self.root_cas,
            'root_dns_key': self.root_dns_key,
            'root_dns_addr': self.root_dns_addr,
            'trc_server': self.trc_server,
            'quorum': self.quorum,
            'trc_quorum': self.trc_quorum,
            'policies': self.policies,
            'signatures': self.signatures,
            'sig_algorithm': self.sig_algorithm,
            'enc_algorithm': self.enc_algorithm}
        return trc_dict

    def parse(self, raw):
        """
        Initializes a TRC object out of a raw TRC.

        @param raw: Raw string produced by packing the TRC.
        """
        try:
            trc = json.loads(raw)
        except (ValueError, KeyError, TypeError):
            logging.error("TRC: JSON format error.")
            return
        self.isd_id = trc['isd_id']
        self.version = trc['version']
        self.time = int(time.time())
        self.core_isps = trc['core_isps']
        self.registry_key = trc['registry_key']
        self.path_key = trc['path_key']
        self.root_cas = trc['root_cas']
        self.root_dns_key = trc['root_dns_key']
        self.root_dns_addr = trc['root_dns_addr']
        self.trc_server = trc['trc_server']
        self.quorum = trc['quorum']
        self.trc_quorum = trc['trc_quorum']
        self.policies = trc['policies']
        self.signatures = trc['signatures']
        self.sig_algorithm = trc['sig_algorithm']
        self.enc_algorithm = trc['enc_algorithm']

    @classmethod
    def from_values(cls, isd_id, version, core_isps, registry_key, path_key,
        root_cas, root_dns_key, root_dns_addr, trc_server, quorum, trc_quorum,
        policies, signatures):
        """
        Generates a TRC instance.

        @param isd_id: ISD's identifier.
        @param version: Version of the TRC file.
        @param core_isps: List of core ISPs and their public keys.
        @param registry_key: Root registry server's public key.
        @param path_key: Path server's public key.
        @param root_cas: List of root CAs and their public keys.
        @param root_dns_key: DNS root's public key.
        @param root_dns_addr: DNS root's address.
        @param trc_server: TRC server's address.
        @param quorum: Number of trust roots that must sign new TRC.
        @param trc_quorum: Number of trust roots that must sign an ISD
            cross-signing cert.
        @param policies: Additional management policies for the ISD.
        @param signatures: Signatures by a quorum of trust roots.
        """
        trc = TRC()
        trc.isd_id = isd_id
        trc.version = version
        trc.time = int(time.time())
        trc.core_isps = core_isps
        trc.registry_key = registry_key
        trc.path_key = path_key
        trc.root_cas = root_cas
        trc.root_dns_key = root_dns_key
        trc.root_dns_addr = root_dns_addr
        trc.trc_server = trc_server
        trc.quorum = quorum
        trc.trc_quorum = trc_quorum
        trc.policies = policies
        trc.signatures = signatures
        trc.sig_algorithm = TRC.SIGN_ALGORITHM
        trc.enc_algorithm = TRC.ENCRYPT_ALGORITHM
        #TODO: signatures
        #trc_dict = trc.get_trc_dict()
        #trc_str = json.dumps(trc_dict, sort_keys=True)
        #trc_str = str.encode(trc_str)
        #signing_key = base64.b64decode(iss_priv_key)
        #cert.signature = base64.standard_b64encode(crypto_sign_ed25519(cert_str, signing_key)).decode('ascii')
        return trc

    def pack(self):
        """
        Packs the TRC into a string.
        """
        trc_dict = self.get_trc_dict()
        trc_str = json.dumps(trc_dict, sort_keys=True, indent=4)
        return trc_str

    def __str__(self):
        return self.pack()
