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
:mod:`trc` --- SCION TRC parser
===========================================
"""

from lib.crypto.asymcrypto import *
import time
import json
import logging
import os
import base64


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
    :ivar core_isps: the list of core ISPs and their public keys.
    :type core_isps: TODO
    :ivar registry_key: the root registry server's public key.
    :type registry_key: TODO
    :ivar path_key: the path server's public key.
    :type path_key: TODO
    :ivar root_cas: the list of root CAs and their public keys.
    :type root_cas: TODO
    :ivar root_dns_key: the DNS root's public key.
    :type root_dns_key: TODO
    :ivar root_dns_addr: the DNS root's address.
    :type root_dns_addr: TODO
    :ivar trc_server: the TRC server's address.
    :type trc_server: TODO
    :ivar quorum: number of trust roots necessary to sign a new TRC.
    :type quorum: int
    :ivar trc_quorum: number of trust roots necessary to sign a new ISD
                      cross-signing certificate.
    :type trc_quorum: int
    :ivar policies: additional management policies for the ISD.
    :type policies: TODO
    :ivar signatures: signatures by a quorum of trust roots.
    :type signatures: TODO
    """

    def __init__(self, trc_file=None):
        """
        Initialize an instance of the class TRC.

        :param trc_file: the name of the TRC file.
        :type trc_file: str
        :returns: the newly created TRC instance.
        :rtype: :class:`TRC`
        """
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
        if trc_file:
            self.parse(trc_file)

    def get_trc_dict(self):
        """
        Return the TRC information.

        :returns: the TRC information.
        :rtype: dict
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
            'signatures': self.signatures}
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

    @classmethod
    def from_values(cls, isd_id, version, core_isps, registry_key, path_key,
        root_cas, root_dns_key, root_dns_addr, trc_server, quorum, trc_quorum,
        policies, signatures):
        """
        Generates a TRC instance.

        :param isd_id: the ISD identifier.
        :type isd_id: int
        :param version: the TRC file version.
        :type version: int
        :param core_isps: the list of core ISPs and their public keys.
        :type core_isps: TODO
        :param registry_key: the root registry server's public key.
        :type registry_key: TODO
        :param path_key: the path server's public key.
        :type path_key: TODO
        :param root_cas: the list of root CAs and their public keys.
        :type root_cas: TODO
        :param root_dns_key: the DNS root's public key.
        :type root_dns_key: TODO
        :param root_dns_addr: the DNS root's address.
        :type root_dns_addr: TODO
        :param trc_server: the TRC server's address.
        :type trc_server: TODO
        :param quorum: number of trust roots necessary to sign a new TRC.
        :type quorum: int
        :param trc_quorum: number of trust roots necessary to sign a new ISD
                           cross-signing certificate.
        :type trc_quorum: int
        :param policies: additional management policies for the ISD.
        :type policies: TODO
        :param signatures: signatures by a quorum of trust roots.
        :type signatures: TODO
        :returns: the newly created TRC instance.
        :rtype: :class:`TRC`
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
        return trc

    def __str__(self):
        """
        Convert the instance in a readable format.

        :returns: the TRC information.
        :rtype: str
        """
        trc_dict = self.get_trc_dict()
        trc_str = json.dumps(trc_dict, sort_keys=True, indent=4)
        return trc_str
