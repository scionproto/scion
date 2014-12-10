#config.py

#Copyright 2014 ETH Zurich

#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
"""
:mod:`config` --- SCION AD Configuration
========================================
"""

import logging


class Config(object):
    """
    Handles parsing and storing a SCION AD config file.

    A config file contains one key:value pair per line.

    :ivar ad_id: the AD identifier.
    :vartype ad_id: int
    :ivar isd_id: the ISD identifier.
    :vartype isd_id: int
    :ivar beacon_server: the address of the beacon server.
    :vartype beacon_server: int
    :ivar path_server: the address of the path server.
    :vartype path_server: int
    :ivar cert_server: the address of the certificate server.
    :vartype cert_server: int
    :ivar private_key_file: the file storing the server's private key.
    :vartype private_key_file: str
    :ivar cert_file: the file storing the server's certificate.
    :vartype cert_file: str
    :ivar master_of_gen_key: the master opaque field generation key file.
    :vartype master_of_gen_key: TODO
    :ivar log_file: the AD log file.
    :vartype log_file: TODO
    :ivar interface_ids: the interface IDs.
    :vartype interface_ids: list
    :ivar n_interface_ids: the number of interface IDs.
    :vartype n_interface_ids: int
    :ivar n_registered_paths: the number of registered paths.
    :vartype n_registered_paths: int
    :ivar n_shortest_up_paths: the number of shortest up-paths.
    :vartype n_shortest_up_paths: int
    :ivar propagation_time: the propagation time.
    :vartype propagation_time: int
    :ivar registration_time: the registration time.
    :vartype registration_time: int
    :ivar reset_time: the reset time.
    :vartype reset_time: int
    :ivar log_level: the logging level of the AD.
    :vartype log_level: int
    :ivar registers_paths: whether or not the AD registers paths.
    :vartype registers_paths: bool
    :ivar is_core_ad: whether or not the AD is a core AD.
    :vartype is_core_ad: bool
    :ivar pcb_queue_size: queue size of the path server.
    :vartype pcb_queue_size: int
    :ivar pcb_gen_period: time period to generate PCBs.
    :vartype pcb_gen_period: int
    """

    def __init__(self, filename=None):
        """
        Constructor.

        :param config_file: the name of the configuration file.
        :type config_file: str
        :returns: the newly created Config instance.
        :rtype: :class:`Config`
        """
        self.master_of_gen_key = None  # Master OF generation key file
        self.master_ad_key = None  # AD certificate server priv key
        self.n_registered_paths = 0  # Number of paths to be registered
        self.n_shortest_up_paths = 0  # Number of shortest up paths
        self.propagation_time = 0  # Propragation time
        self.registration_time = 0  # Registration time
        self.reset_time = 0  # Time to reset the PCB tables
        self.registers_paths = False  # True if this AD registers paths
        self.pcb_queue_size = 0  # PCB queue size for the beacon server
        self.path_server_queue_size = 0  # Path server queue size for paths
        self._filename = filename

    def parse(self):
        """
        Parses a SCION AD config file and populates the object's attributes.
        """
        assert isinstance(self._filename, str)
        with open(self._filename) as file_handler:
            lines = [line.rstrip() for line in file_handler]

        for line in lines:
            # Skip commented lines
            if line[0] == '#':
                continue
            key, val = line.split(' ', 1)
            if key == "NumRegisteredPaths":
                self.n_registered_paths = int(val)
            elif key == "MasterOFGKey":
                self.master_of_gen_key = val
            elif key == "RegisterTime":
                self.registration_time = int(val)
            elif key == "PropagateTime":
                self.propagation_time = int(val)
            elif key == "ResetTime":
                self.reset_time = int(val)
            elif key == "RegisterPath":
                self.registers_paths = bool(int(val))
            elif key == "MasterADKey":
                self.master_ad_key = val
            elif key == "PCBQueueSize":
                self.pcb_queue_size = int(val)
            elif key == "PSQueueSize":
                self.path_server_queue_size = int(val)
            elif key == "NumShortestUPs":
                self.n_shortest_up_paths = int(val)
            else:
                logging.warning("Unknown config option: '%s'", key)
