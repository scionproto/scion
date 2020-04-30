# Copyright 2014 ETH Zurich
# Copyright 2018 ETH Zurich, Anapaya Systems
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
:mod:`prometheus` --- SCION topology prometheus generator
=============================================
"""
# Stdlib
import os
from collections import defaultdict

# External packages
import yaml

# SCION
from lib.defines import DOCKER_COMPOSE_CONFIG_VERSION, PROM_FILE
from lib.util import write_file
from topology.common import (
    ArgsTopoDicts,
    prom_addr,
    prom_addr_dispatcher,
    sciond_ip,
)

CS_PROM_PORT = 30452
SCIOND_PROM_PORT = 30455
SIG_PROM_PORT = 30456
CO_PROM_PORT = 30457
DISP_PROM_PORT = 30441
DEFAULT_BR_PROM_PORT = 30442

PROM_DC_FILE = "prom-dc.yml"


class PrometheusGenArgs(ArgsTopoDicts):
    def __init__(self, args, topo_dicts, networks):
        super().__init__(args, topo_dicts)
        self.networks = networks


class PrometheusGenerator(object):
    PROM_DIR = "prometheus"
    TARGET_FILES = {
        "BorderRouters": "br.yml",
        "ControlService": "cs.yml",
        "Sciond": "sd.yml",
        "Dispatcher": "disp.yml",
    }
    JOB_NAMES = {
        "BorderRouters": "BR",
        "ControlService": "CS",
        "Sciond": "SD",
        "Dispatcher": "dispatcher",
    }

    def __init__(self, args):
        """
        :param PrometheusGenArgs args: Contains the passed command line arguments and topo dicts.
        """
        self.args = args
        self.output_base = os.environ.get('SCION_OUTPUT_BASE', os.getcwd())

    def generate(self):
        config_dict = {}
        for topo_id, as_topo in self.args.topo_dicts.items():
            ele_dict = defaultdict(list)
            for br_id, br_ele in as_topo["border_routers"].items():
                a = prom_addr(br_ele["internal_addr"], DEFAULT_BR_PROM_PORT)
                ele_dict["BorderRouters"].append(a)
            for elem_id, elem in as_topo["control_service"].items():
                a = prom_addr(elem["addr"], CS_PROM_PORT)
                ele_dict["ControlService"].append(a)
            if self.args.docker:
                host_dispatcher = prom_addr_dispatcher(self.args.docker, topo_id,
                                                       self.args.networks, DISP_PROM_PORT, "")
                br_dispatcher = prom_addr_dispatcher(self.args.docker, topo_id,
                                                     self.args.networks, DISP_PROM_PORT, "br")
                ele_dict["Dispatcher"] = [host_dispatcher, br_dispatcher]
            sd_prom_addr = '[%s]:%d' % (sciond_ip(self.args.docker, topo_id, self.args.networks),
                                        SCIOND_PROM_PORT)
            ele_dict["Sciond"].append(sd_prom_addr)
            config_dict[topo_id] = ele_dict
        self._write_config_files(config_dict)
        self._write_dc_file()
        self._write_disp_file()

    def _write_config_files(self, config_dict):
        targets_paths = defaultdict(list)
        for topo_id, ele_dict in config_dict.items():
            base = topo_id.base_dir(self.args.output_dir)
            as_local_targets_path = {}
            for ele_type, target_list in ele_dict.items():
                local_path = os.path.join(self.PROM_DIR, self.TARGET_FILES[ele_type])
                targets_path = os.path.join(topo_id.base_dir(''), local_path)
                targets_paths[self.JOB_NAMES[ele_type]].append(targets_path)
                as_local_targets_path[self.JOB_NAMES[ele_type]] = [local_path]
                self._write_target_file(base, target_list, ele_type)
            self._write_config_file(os.path.join(base, PROM_FILE), as_local_targets_path)
        if not self.args.docker:
            targets_paths["dispatcher"] = [os.path.join("dispatcher", "prometheus", "disp.yml")]
        self._write_config_file(os.path.join(self.args.output_dir, PROM_FILE), targets_paths)

    def _write_config_file(self, config_path, job_dict):
        scrape_configs = []
        for job_name, file_paths in job_dict.items():
            scrape_configs.append({
                'job_name': job_name,
                'file_sd_configs': [{'files': file_paths}],
            })
        config = {
            'global': {
                'scrape_interval': '5s',
                'evaluation_interval': '15s',
                'external_labels': {
                    'monitor': 'scion-monitor'
                }
            },
            'scrape_configs': scrape_configs,
        }
        write_file(config_path, yaml.dump(config, default_flow_style=False))

    def _write_target_file(self, base_path, target_addrs, ele_type):
        targets_path = os.path.join(base_path, self.PROM_DIR, self.TARGET_FILES[ele_type])
        target_config = [{'targets': target_addrs}]
        write_file(targets_path, yaml.dump(target_config, default_flow_style=False))

    def _write_disp_file(self):
        if self.args.docker:
            return
        targets_path = os.path.join(self.args.output_dir, "dispatcher",
                                    PrometheusGenerator.PROM_DIR, "disp.yml")
        target_config = [{'targets': [prom_addr_dispatcher(False, None, None,
                                                           DISP_PROM_PORT, None)]}]
        write_file(targets_path, yaml.dump(target_config, default_flow_style=False))

    def _write_dc_file(self):
        name_prefix = 'prometheus'
        name = '%s_docker' % name_prefix if self.args.in_docker else name_prefix
        prom_dc = {
            'version': DOCKER_COMPOSE_CONFIG_VERSION,
            'services': {
                name_prefix: {
                    'image': 'prom/prometheus:v2.6.0',
                    'container_name': name,
                    'network_mode': 'host',
                    'volumes': [
                        self.output_base + '/gen:/prom-config:ro'
                    ],
                    'command': ['--config.file', '/prom-config/prometheus.yml'],
                }
            }
        }
        write_file(os.path.join(self.args.output_dir, PROM_DC_FILE),
                   yaml.dump(prom_dc, default_flow_style=False))
