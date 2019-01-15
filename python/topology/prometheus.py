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
from lib.defines import PROM_FILE
from lib.util import write_file
from topology.common import (
    ArgsTopoDicts,
    prom_addr_br,
    prom_addr_infra,
    prom_addr_sciond,
)

PS_PROM_PORT = 30453
BS_PROM_PORT = 30452
CS_PROM_PORT = 30454
SCIOND_PROM_PORT = 30455
SIG_PROM_PORT = 30456
DEFAULT_BR_PROM_PORT = 30442


class PrometheusGenArgs(ArgsTopoDicts):
    def __init__(self, args, topo_dicts, networks, port_gen=None):
        super().__init__(args, topo_dicts, port_gen)
        self.networks = networks


class PrometheusGenerator(object):
    PROM_DIR = "prometheus"
    TARGET_FILES = {
        "BorderRouters": "br.yml",
        "BeaconService": "bs.yml",
        "CertificateService": "cs.yml",
        "PathService": "ps.yml",
        "Sciond": "sd.yml",
    }
    JOB_NAMES = {
        "BorderRouters": "BR",
        "BeaconService": "BS",
        "CertificateService": "CS",
        "PathService": "PS",
        "Sciond": "SD",
    }

    def __init__(self, args):
        """
        :param PrometheusGenArgs args: Contains the passed command line arguments and topo dicts.
        """
        self.args = args

    def generate(self):
        config_dict = {}
        for topo_id, as_topo in self.args.topo_dicts.items():
            ele_dict = defaultdict(list)
            for br_id, br_ele in as_topo["BorderRouters"].items():
                ele_dict["BorderRouters"].append(prom_addr_br(br_id, br_ele, DEFAULT_BR_PROM_PORT))
            for elem_id, elem in as_topo["BeaconService"].items():
                prom_addr = prom_addr_infra(self.args.docker, elem_id, elem, BS_PROM_PORT)
                ele_dict["BeaconService"].append(prom_addr)
            for elem_id, elem in as_topo["PathService"].items():
                prom_addr = prom_addr_infra(self.args.docker, elem_id, elem, PS_PROM_PORT)
                ele_dict["PathService"].append(prom_addr)
            for elem_id, elem in as_topo["CertificateService"].items():
                prom_addr = prom_addr_infra(self.args.docker, elem_id, elem, CS_PROM_PORT)
                ele_dict["CertificateService"].append(prom_addr)
            sd_prom_addr = prom_addr_sciond(self.args.docker, topo_id,
                                            self.args.networks, SCIOND_PROM_PORT)
            ele_dict["Sciond"].append(sd_prom_addr)
            config_dict[topo_id] = ele_dict
        self._write_config_files(config_dict)

    def _write_config_files(self, config_dict):
        targets_paths = defaultdict(list)
        for topo_id, ele_dict in config_dict.items():
            base = topo_id.base_dir(self.args.output_dir)
            as_local_targets_path = {}
            for ele_type, target_list in ele_dict.items():
                targets_path = os.path.join(base, self.PROM_DIR, self.TARGET_FILES[ele_type])
                targets_paths[self.JOB_NAMES[ele_type]].append(targets_path)
                as_local_targets_path[self.JOB_NAMES[ele_type]] = [targets_path]
                self._write_target_file(base, target_list, ele_type)
            self._write_config_file(os.path.join(base, PROM_FILE), as_local_targets_path)
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
