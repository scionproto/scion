"""
server.py

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

import logging


class Config(object):
    """
    Handles parsing and storing a SCION AD config file.

    A config file contains one key:value pair per line.
    """

    def __init__(self, filename=None):
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
        Parses a SCION AD config file and populates the fields.
        """
        assert isinstance(self._filename, str)
        with open(self._filename) as file:
            lines = [line.rstrip() for line in file]

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


# For testing purposes
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: %s <config_file>" % sys.argv[0])
        sys.exit()
    config = Config(sys.argv[1])
    config.parse()
    print("Parsing done.\n")
