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
from unittest.mock import patch

# SCION
from lib.config import Config


class BaseLibConfig(object):
    """
    Base class for lib.config unit tests
    """
    ATTRS_TO_KEYS = {
        'master_ad_key': 'MasterADKey',
        'propagation_time': 'PropagateTime',
        'registration_time': 'RegisterTime',
        'registers_paths': 'RegisterPath',
        'mtu': 'MTU',
        'cert_ver': 'CertChainVersion',
    }


class TestConfigInit(BaseLibConfig):
    """
    Unit tests for lib.config.Config.__init__
    """
    def test_basic(self):
        config = Config()
        for attr in self.ATTRS_TO_KEYS.keys():
            ntools.eq_(getattr(config, attr), 0)


class TestConfigFromFile(BaseLibConfig):
    """
    Unit tests for lib.config.Config.from_file
    """
    @patch("lib.config.Config.from_dict")
    @patch("lib.config.load_yaml_file")
    def test_success(self, load, from_dict):
        from_dict.return_value = "All ok"
        ntools.eq_(Config.from_file("path"), "All ok")
        load.assert_called_once_with("path")


class TestConfigFromDict(BaseLibConfig):
    """
    Unit tests for lib.config.Config.from_dict
    """
    @patch("lib.config.Config.parse_dict")
    def test_basic(self, parse_dict):
        ntools.assert_is_instance(Config.from_dict("dict"), Config)
        parse_dict.assert_called_once_with("dict")


class TestConfigParseDict(BaseLibConfig):
    """
    Unit tests for lib.config.Config.parse_dict
    """
    config_dict = {
        "CertChainVersion": 0,
        "MasterADKey": "Xf93o3Wz/4Gb0m6CXEaxag==",
        "PropagateTime": 5,
        "RegisterPath": 1,
        "RegisterTime": 5,
        "MTU": 1500,
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
            if attr in ['master_of_gen_key', 'master_ad_key']:
                ntools.eq_(value, base64.b64decode(config_dict[key]))
            else:
                ntools.eq_(value, config_dict[key])


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
