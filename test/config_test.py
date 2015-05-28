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
:mod:`config_test` --- lib.config unit tests
======================================================
"""
# Stdlib
import json
import os

# External packages
import nose.tools as ntools

# SCION
from lib.config import Config
from lib.defines import TOPOLOGY_PATH


class BaseLibConfig(object):
    """
    Base class for lib.config unit tests
    """
    config_path = os.path.join(TOPOLOGY_PATH,
                               'ISD1', 'configurations', 'ISD:1-AD:10.conf')
    config_json = json.load(open(config_path))

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
        'cert_chain_version': 'CertChainVersion',
    }

    def _compare_attributes(self, config, config_dict):
        ntools.eq_(len(config.__dict__),
                   len(self.ATTRS_TO_KEYS),
                   "Unequal number of keys/attributes: is something missing?")
        for attr, key in self.ATTRS_TO_KEYS.items():
            ntools.eq_(getattr(config, attr), config_dict[key])


class TestConfigInit(BaseLibConfig):
    """
    Unit tests for lib.config.Config.__init__
    """
    def test_basic(self):
        config = Config()
        for attr in self.ATTRS_TO_KEYS.keys():
            ntools.assert_true(hasattr(config, attr),
                               "No attribute found: {}".format(attr))
            ntools.eq_(getattr(config, attr), 0)


class TestConfigFromDict(BaseLibConfig):
    """
    Unit tests for lib.config.Config.from_dict
    """
    def test_basic(self):
        config = Config.from_dict(self.config_json)
        ntools.assert_true(isinstance(config, Config))
        self._compare_attributes(config, self.config_json)

    @ntools.raises(KeyError)
    def test_invalid_dict(self):
        Config.from_dict({'a': 'b'})


class TestConfigFromFile(BaseLibConfig):
    """
    Unit tests for lib.config.Config.from_file
    """
    def test_basic(self):
        config = Config.from_file(self.config_path)
        ntools.assert_true(isinstance(config, Config))
        self._compare_attributes(config, self.config_json)

    @ntools.raises(FileNotFoundError)
    def test_no_file(self):
        Config.from_file('')
