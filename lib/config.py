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
:mod:`config` --- SCION configuration parser
========================================
"""

import json
import logging


class Config(object):
    """
    The Config class parses the configuration file of an AD and stores such
    information for further use.

    :ivar master_of_gen_key: the master opaque field generation key file.
    :type master_of_gen_key: int
    :ivar master_ad_key: AD certificate servers priv key.
    :type master_ad_key: int
    :ivar n_registered_paths: the number of registered paths.
    :type n_registered_paths: int
    :ivar n_shortest_up_paths: the number of shortest up-paths.
    :type n_shortest_up_paths: int
    :ivar propagation_time: the propagation time.
    :type propagation_time: int
    :ivar registration_time: the registration time.
    :type registration_time: int
    :ivar reset_time: the reset time.
    :type reset_time: int
    :ivar registers_paths: whether or not the AD registers paths.
    :type registers_paths: int
    :ivar pcb_queue_size: PCB queue size for the beacon servers.
    :type pcb_queue_size: int
    :ivar path_server_queue_size: path queue size for the path servers.
    :type path_server_queue_size: int
    """

    def __init__(self, config_file=None):
        """
        Initialize an instance of the class Config.

        :param config_file: the name of the configuration file.
        :type config_file: str
        :returns: the newly created Config instance.
        :rtype: :class:`Config`
        """
        self.master_of_gen_key = 0
        self.master_ad_key = 0
        self.n_registered_paths = 0
        self.n_shortest_up_paths = 0
        self.propagation_time = 0
        self.registration_time = 0
        self.reset_time = 0
        self.registers_paths = 0
        self.pcb_queue_size = 0
        self.path_server_queue_size = 0
        if config_file:
            self.parse(config_file)

    def parse(self, config_file):
        """
        Parse a configuration file and populate the instance's attributes.

        :param config_file: the name of the configuration file.
        :type config_file: str
        """
        try:
            with open(config_file) as conf_fh:
                config = json.load(conf_fh)
        except (ValueError, KeyError, TypeError):
            logging.error("Config: JSON format error.")
            return
        self.master_of_gen_key = config['MasterOFGKey']
        self.master_ad_key = config['MasterADKey']
        self.n_registered_paths = config['NumRegisteredPaths']
        self.n_shortest_up_paths = config['NumShortestUPs']
        self.propagation_time = config['PropagateTime']
        self.registration_time = config['RegisterTime']
        self.reset_time = config['ResetTime']
        self.registers_paths = config['RegisterPath']
        self.pcb_queue_size = config['PCBQueueSize']
        self.path_server_queue_size = config['PSQueueSize']
