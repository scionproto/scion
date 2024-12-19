# Copyright 2014 ETH Zurich
# Copyright 2018 ETH Zurich, Anapaya Systems
# Copyright 2019 Anapaya Systems
# Copyright 2023 SCION Association
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
:mod:`monitoring` --- SCION topology monitoring generator
=========================================================
"""

# Stdlib
import os
from collections import defaultdict
from typing import Mapping

# External packages
import yaml

# SCION
from topology.defines import DOCKER_COMPOSE_CONFIG_VERSION, PROM_FILE
from topology.util import write_file
from topology.common import (
    ArgsTopoDicts,
    prom_addr,
    prom_addr_dispatcher,
    sciond_ip,
)
from topology.net import (
    NetworkDescription,
    IPNetwork,
)

CS_PROM_PORT = 30452
SCIOND_PROM_PORT = 30455
SIG_PROM_PORT = 30456
DISP_PROM_PORT = 30441
DEFAULT_BR_PROM_PORT = 30442
MONITORING_DC_FILE = "monitoring-dc.yml"


class MonitoringGenArgs(ArgsTopoDicts):
    def __init__(self, args, topo_dicts, networks: Mapping[IPNetwork, NetworkDescription]):
        super().__init__(args, topo_dicts)
        self.networks = networks


class MonitoringGenerator(object):
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
    JOB_METRIC_RELABEL = {
        # "BR": "<relabel dict>"
    }

    def __init__(self, args):
        """
        :param MonitoringGenArgs args: Contains the passed command line arguments and topo dicts.
        """
        self.args = args
        self.output_base = os.environ.get('SCION_OUTPUT_BASE', os.getcwd())
        self.local_jaeger_dir = os.path.join('traces')
        self.docker_jaeger_dir = os.path.join(self.output_base, self.local_jaeger_dir)

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

        # For yeager
        os.makedirs(os.path.join(self.local_jaeger_dir, 'data'), exist_ok=True)
        os.makedirs(os.path.join(self.local_jaeger_dir, 'key'), exist_ok=True)

    def _write_config_files(self, config_dict):
        # For Prometheus
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
            job_scrape_config = {
                'job_name': job_name,
                'file_sd_configs': [{'files': file_paths}],
            }
            relabels = self.JOB_METRIC_RELABEL.get(job_name)
            if relabels is not None:
                job_scrape_config['metric_relabel_configs'] = relabels
            scrape_configs.append(job_scrape_config)
        config = {
            'global': {
                'scrape_interval': '1s',
                'evaluation_interval': '1s',
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
                                    self.PROM_DIR, "disp.yml")
        target_config = [{'targets': [prom_addr_dispatcher(False, None, None,
                                                           DISP_PROM_PORT, None)]}]
        write_file(targets_path, yaml.dump(target_config, default_flow_style=False))

    def _write_dc_file(self):
        # Merged yeager and prometheus files.
        monitoring_dc = {
            'version': DOCKER_COMPOSE_CONFIG_VERSION,
            'name': 'monitoring',
            'services': {
                'prometheus': {
                    'image': 'prom/prometheus:v2.47.2',
                    'network_mode': 'host',
                    'volumes': [
                        self.output_base + '/gen:/prom-config:ro'
                    ],
                    'command': ['--config.file', '/prom-config/prometheus.yml'],
                },
                'jaeger': {
                    'image': 'jaegertracing/all-in-one:1.22.0',
                    'user': '%s:%s' % (str(os.getuid()), str(os.getgid())),
                    'ports': [
                        '6831:6831/udp',
                        '16686:16686'
                    ],
                    'environment': [
                        'SPAN_STORAGE_TYPE=badger',
                        'BADGER_EPHEMERAL=false',
                        'BADGER_DIRECTORY_VALUE=/badger/data',
                        'BADGER_DIRECTORY_KEY=/badger/key',
                    ],
                    'volumes': [
                        '%s:/badger:rw' % self.docker_jaeger_dir,
                    ],
                }
            }
        }
        write_file(os.path.join(self.args.output_dir, MONITORING_DC_FILE),
                   yaml.dump(monitoring_dc, default_flow_style=False))
