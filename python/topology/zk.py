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
from shutil import copyfile
# External packages
import yaml
# SCION
from lib.util import write_file
from topology.common import _gen_zk_entry

ZK_CONF = 'zk-dc.yml'


class ZKGenerator(object):
    def __init__(self, out_dir, topo_config, in_docker, docker):
        self.out_dir = out_dir
        self.topo_config = topo_config
        self.in_docker = in_docker
        self.docker = docker
        self.zk_conf = {'version': '3', 'services': {}}
        self.output_base = os.environ.get('SCION_OUTPUT_BASE', os.getcwd())
        self.user_spec = os.environ.get('SCION_USERSPEC', '$LOGNAME')

    def generate(self):
        if "zookeepers" not in self.topo_config.get("defaults", {}):
            logging.critical("No zookeeper configured in the topology!")
            sys.exit(1)
        zk_conf = self.topo_config["defaults"]["zookeepers"]
        addr = zk_conf[1].get("addr", None)
        port = zk_conf[1].get("port", None)
        zk_entry = _gen_zk_entry(addr, port, self.in_docker, self.docker)
        name = 'zookeeper_docker' if self.in_docker else 'zookeeper'
        entry = {
            'image': 'zookeeper:latest',
            'container_name': name,
            'environment': {
                'ZOO_USER': self.user_spec,
            },
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                self.output_base + '/logs:/logs:rw'
            ],
            'ports': [
                zk_entry["Addr"] + ":" + str(zk_entry["L4Port"]) + ':2181'
            ]
        }

        if self.in_docker:
            entry['tmpfs'] = '/datalog'
            entry['tmpfs'] = '/data'
            cfg_dir = os.path.join(self.output_base, self.out_dir, "docker/zk")
            entry['volumes'].append(cfg_dir + ":/conf")
        else:
            entry['volumes'].append('/run/shm/host-zk:/datalog:rw')
            entry['volumes'].append('/var/lib/zookeeper:/data:rw')
            entry['volumes'].append(self.output_base + '/docker/zk:/conf')

        self.zk_conf['services'][name] = entry
        write_file(os.path.join(self.out_dir, ZK_CONF),
                   yaml.dump(self.zk_conf, default_flow_style=False))

        if self.in_docker:
            # Copy zookeeper config files
            cfg_dir = "docker/zk"
            cfg_path = os.path.join(self.out_dir, cfg_dir)
            os.makedirs(cfg_path)
            files = ["zoo.cfg", "log4j.properties"]
            for f in files:
                copyfile(os.path.join(os.environ['PWD'], cfg_dir, f), os.path.join(cfg_path, f))
