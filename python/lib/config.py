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
:mod:`config` --- SCION configuration parser
============================================
"""
# Stdlib
import base64
import logging

# SCION
from lib.defines import DEFAULT_SEGMENT_TTL
from lib.util import load_yaml_file


class Config(object):
    """
    The Config class parses the configuration file of an AS and stores such
    information for further use.

    :ivar bytes master_as_key: AS certificate servers priv key.
    :ivar int propagation_time: the interval at which PCBs are propagated.
    :ivar int registration_time: the interval at which paths are registered.
    :ivar int registers_paths: whether or not the AS registers paths.
    :ivar int cert_ver: initial version of the certificate chain.
    :ivar int segment_ttl: the TTL of path segments registered by this AS (in seconds).
    :ivar int revocation_tree_ttl: the TTL of one revocation tree (in seconds).
    """

    def __init__(self):  # pragma: no cover
        self.master_as_key = 0
        self.propagation_time = 0
        self.registration_time = 0
        self.registers_paths = 0
        self.cert_ver = 0
        self.segment_ttl = 0
        self.revocation_tree_ttl = 0

    @classmethod
    def from_file(cls, config_file):  # pragma: no cover
        """
        Create a Config instance from the configuration file.

        :param str config_file: path to the configuration file
        :returns: the newly created Config instance
        :rtype: :class:`Config`
        """
        return cls.from_dict(load_yaml_file(config_file))

    @classmethod
    def from_dict(cls, config_dict):  # pragma: no cover
        """
        Create a Config instance from the dictionary.

        :param dict config_dict: dictionary representation of configuration
        :returns: the newly created Config instance
        :rtype: :class:`Config`
        """
        config = cls()
        config.parse_dict(config_dict)
        return config

    def parse_dict(self, config):
        """
        Parse a configuration file and populate the instance's attributes.

        :param dict config: the name of the configuration file.
        """
        self.master_as_key = base64.b64decode(config['MasterASKey'])
        self.propagation_time = config['PropagateTime']
        self.registration_time = config['RegisterTime']
        self.registers_paths = config['RegisterPath']
        self.cert_ver = config['CertChainVersion']
        self.segment_ttl = config.get('PathSegmentTTL', DEFAULT_SEGMENT_TTL)
        self.revocation_tree_ttl = config.get('RevocationTreeTTL', self.segment_ttl)
        if self.revocation_tree_ttl < self.segment_ttl:
            logging.warning("RevocationTreeTTL shorter than PathSegmentTTL (%ds vs %ds). "
                            "Setting RevocationTreeTTL to %ds",
                            self.segment_ttl, self.revocation_tree_ttl, self.segment_ttl)
            self.revocation_tree_ttl = self.segment_ttl
