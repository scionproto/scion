# Copyright 2015 ETH Zurich
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
:mod:`lib_config_test` --- lib.config unit tests
================================================
"""
# Stdlib
import base64

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.config import Config


class BaseLibConfig(object):
    """
    Base class for lib.config unit tests
    """
    ATTRS_TO_KEYS = {
        'master_as_key': 'MasterASKey',
        'propagation_time': 'PropagateTime',
        'registration_time': 'RegisterTime',
        'registers_paths': 'RegisterPath',
        'cert_ver': 'CertChainVersion',
        'segment_ttl': 'PathSegmentTTL',
        'revocation_tree_ttl': 'RevocationTreeTTL'
    }


class TestConfigParseDict(BaseLibConfig):
    """
    Unit tests for lib.config.Config.parse_dict
    """
    config_dict = {
        "CertChainVersion": 0,
        "MasterASKey": "Xf93o3Wz/4Gb0m6CXEaxag==",
        "PropagateTime": 5,
        "RegisterPath": 1,
        "RegisterTime": 5,
        "PathSegmentTTL": 6 * 60 * 60,
        "RevocationTreeTTL": 6 * 60 * 60,
    }

    def test_basic(self):
        cfg = Config()
        cfg.parse_dict(self.config_dict)
        self._compare_attributes(cfg, self.config_dict)

    def _compare_attributes(self, config, config_dict):
        ntools.eq_(len(config.__dict__),
                   len(self.ATTRS_TO_KEYS),
                   "Unequal number of keys/attributes: is something missing?")
        for attr, key in self.ATTRS_TO_KEYS.items():
            value = getattr(config, attr)
            if attr in ['master_of_gen_key', 'master_as_key']:
                ntools.eq_(value, base64.b64decode(config_dict[key]))
            else:
                ntools.eq_(value, config_dict[key])


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
