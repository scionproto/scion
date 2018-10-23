# Copyright 2018 ETH Zurich
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

# Stdlib
import logging
import os
import sys
# External packages
import yaml
# SCION
from lib.util import write_file
from topology.common import gen_zk_entry, ArgsTopoConfig

ZK_CONF = 'zk-dc.yml'


class ZKGenArgs(ArgsTopoConfig):
    pass


class ZKGenerator(object):
    def __init__(self, args):
        """
        :param ZKGenArgs args: Contains the passed command line arguments and topo dicts.
        """
        self.args = args
        self.zk_conf = {'version': '3', 'services': {}}

    def generate(self):
        if "zookeepers" not in self.args.config.get("defaults", {}):
            logging.critical("No zookeeper configured in the topology!")
            sys.exit(1)
        zk_conf = self.args.config["defaults"]["zookeepers"]
        addr = zk_conf[1].get("addr", None)
        port = zk_conf[1].get("port", None)
        zk_entry = gen_zk_entry(addr, port, self.args.in_docker, self.args.docker)
        name = 'zookeeper_docker' if self.args.in_docker else 'zookeeper'
        entry = {
            'image': 'zookeeper:latest',
            'container_name': name,
            'environment': {
                'ZOO_MAX_CLIENT_CNXNS': 0,
            },
            'tmpfs': [
                '/datalog'
            ],
            'ports': [
                zk_entry["Addr"] + ":" + str(zk_entry["L4Port"]) + ':2181'
            ]
        }

        self.zk_conf['services'][name] = entry
        write_file(os.path.join(self.args.output_dir, ZK_CONF),
                   yaml.dump(self.zk_conf, default_flow_style=False))
