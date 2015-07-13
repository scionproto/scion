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
from unittest.mock import patch, mock_open

# SCION
from lib.config import Config
from test.testcommon import SCIONTestException


class BaseLibConfig(object):
    """
    Base class for lib.config unit tests
    """
    ATTRS_TO_KEYS = {
        'master_of_gen_key': 'MasterOFGKey',
        'master_ad_key': 'MasterADKey',
        'n_registered_paths': 'NumRegisteredPaths',
        'n_shortest_up_paths': 'NumShortestUPs',
        'propagation_time': 'PropagateTime',
        'registration_time': 'RegisterTime',
        'reset_time': 'ResetTime',
        'registers_paths': 'RegisterPath',
        'pcb_queue_size': 'PCBQueueSize',
        'path_server_queue_size': 'PSQueueSize',
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
    @patch("lib.config.json.load")
    @patch("builtins.open", new_callable=mock_open)
    def test_success(self, io_open, load, from_dict):
        from_dict.return_value = "All ok"
        ntools.eq_(Config.from_file("path"), "All ok")
        io_open.assert_called_once_with("path")
        load.assert_called_once_with(io_open.return_value)

    @patch("lib.config.Config.from_dict")
    @patch("lib.config.json.load")
    @patch("builtins.open", new_callable=mock_open)
    def _check_error(self, excp, _, load, from_dict):
        # Setup
        load.side_effect = excp  # Raise an exception when json.load() is called
        from_dict.side_effect = SCIONTestException("from_dict should not "
                                                   "have been called")
        # Call
        ntools.eq_(Config.from_file("path"), None)

    def test_error(self):
        for excp in (ValueError, KeyError, TypeError):
            yield self._check_error, excp


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
    config_json = {
        "CertChainVersion": 0,
        "MasterADKey": "Xf93o3Wz/4Gb0m6CXEaxag==",
        "MasterOFGKey": "8clgjqBlI6f3FwAZ419i4A==",
        "NumRegisteredPaths": 10,
        "NumShortestUPs": 3,
        "PCBQueueSize": 10,
        "PSQueueSize": 10,
        "PropagateTime": 5,
        "RegisterPath": 1,
        "RegisterTime": 5,
        "ResetTime": 600
    }

    def test_basic(self):
        cfg = Config()
        cfg.parse_dict(self.config_json)
        self._compare_attributes(cfg, self.config_json)

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
