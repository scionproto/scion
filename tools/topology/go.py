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
:mod:`go` --- SCION topology go generator
=============================================
"""
# Stdlib
import os
import toml
from typing import Mapping

# SCION
from topology.util import write_file
from topology.common import (
    ArgsBase,
    DISP_CONFIG_NAME,
    docker_host,
    prom_addr,
    prom_addr_dispatcher,
    sciond_ip,
    sciond_name,
    translate_features,
    SD_API_PORT,
    SD_CONFIG_NAME,
)

from topology.net import socket_address_str, NetworkDescription, IPNetwork

from topology.monitoring import (
    CS_PROM_PORT,
    DEFAULT_BR_PROM_PORT,
    SCIOND_PROM_PORT,
    DISP_PROM_PORT,
)


class GoGenArgs(ArgsBase):
    def __init__(self, args, topo_config, topo_dicts,
                 networks: Mapping[IPNetwork, NetworkDescription]):
        """
        :param object args: Contains the passed command line arguments as named attributes.
        :param dict topo_config: The parsed topology config.
        :param dict topo_dicts: The generated topo dicts from TopoGenerator.
        """
        super().__init__(args)
        self.config = topo_config
        self.topo_dicts = topo_dicts
        self.networks = networks


class GoGenerator(object):
    def __init__(self, args):
        """
        :param GoGenArgs args: Contains the passed command line arguments and topo dicts.
        """
        self.args = args
        self.log_dir = '/share/logs' if args.docker else 'logs'
        self.db_dir = '/share/cache' if args.docker else 'gen-cache'
        self.log_level = 'debug'

    def generate_br(self):
        for topo_id, topo in self.args.topo_dicts.items():
            for k, v in topo.get("border_routers", {}).items():
                base = topo_id.base_dir(self.args.output_dir)
                br_conf = self._build_br_conf(topo_id, topo["isd_as"], base, k, v)
                write_file(os.path.join(base, "%s.toml" % k), toml.dumps(br_conf))

    def _build_br_conf(self, topo_id, ia, base, name, v):
        config_dir = '/etc/scion' if self.args.docker else base
        raw_entry = {
            'general': {
                'id': name,
                'config_dir': config_dir,
            },
            'log': self._log_entry(name),
            'metrics': {
                'prometheus': prom_addr(v['internal_addr'], DEFAULT_BR_PROM_PORT),
            },
            'features': translate_features(self.args.features),
            'api': {
                'addr': prom_addr(v['internal_addr'], DEFAULT_BR_PROM_PORT+700)
            }
        }
        return raw_entry

    def generate_control_service(self):
        for topo_id, topo in self.args.topo_dicts.items():
            ca = self.args.config["ASes"][str(topo_id)].get("issuing", False)
            for elem_id, elem in topo.get("control_service", {}).items():
                # only a single Go-BS per AS is currently supported
                if elem_id.endswith("-1"):
                    base = topo_id.base_dir(self.args.output_dir)
                    bs_conf = self._build_control_service_conf(
                        topo_id, topo["isd_as"], base, elem_id, elem, ca)
                    write_file(os.path.join(base, "%s.toml" % elem_id),
                               toml.dumps(bs_conf))

    def _build_control_service_conf(self, topo_id, ia, base, name, infra_elem, ca):
        config_dir = '/etc/scion' if self.args.docker else base
        raw_entry = {
            'general': {
                'id': name,
                'config_dir': config_dir,
            },
            'log': self._log_entry(name),
            'trust_db': {
                'connection': os.path.join(self.db_dir, '%s.trust.db' % name),
            },
            'beacon_db':     {
                'connection': os.path.join(self.db_dir, '%s.beacon.db' % name),
            },
            'path_db': {
                'connection': os.path.join(self.db_dir, '%s.path.db' % name),
            },
            'tracing': self._tracing_entry(),
            'metrics': self._metrics_entry(infra_elem, CS_PROM_PORT),
            'api': self._api_entry(infra_elem, CS_PROM_PORT+700),
            'features': translate_features(self.args.features),
        }
        if ca:
            raw_entry['ca'] = {'mode': 'in-process'}
        return raw_entry

    def generate_sciond(self):
        for topo_id, topo in self.args.topo_dicts.items():
            base = topo_id.base_dir(self.args.output_dir)
            sciond_conf = self._build_sciond_conf(topo_id, topo["isd_as"], base)
            write_file(os.path.join(base, SD_CONFIG_NAME), toml.dumps(sciond_conf))

    def _build_sciond_conf(self, topo_id, ia, base):
        name = sciond_name(topo_id)
        config_dir = '/etc/scion' if self.args.docker else base
        ip = sciond_ip(self.args.docker, topo_id, self.args.networks)
        raw_entry = {
            'general': {
                'id': name,
                'config_dir': config_dir,
            },
            'log': self._log_entry(name),
            'trust_db': {
                'connection': os.path.join(self.db_dir, '%s.trust.db' % name),
            },
            'path_db': {
                'connection': os.path.join(self.db_dir, '%s.path.db' % name),
            },
            'sd': {
                'address': socket_address_str(ip, SD_API_PORT),
            },
            'tracing': self._tracing_entry(),
            'metrics': {
                'prometheus': socket_address_str(ip, SCIOND_PROM_PORT)
            },
            'features': translate_features(self.args.features),
            'api': {
                'addr': socket_address_str(ip, SD_API_PORT+700),
            }
        }
        return raw_entry

    def generate_disp(self):
        if self.args.docker:
            self._gen_disp_docker()
        else:
            elem_dir = os.path.join(self.args.output_dir, "dispatcher")
            config_file_path = os.path.join(elem_dir, DISP_CONFIG_NAME)
            write_file(config_file_path, toml.dumps(self._build_disp_conf(
                "dispatcher")))

    def _gen_disp_docker(self):
        for topo_id, topo in self.args.topo_dicts.items():
            base = topo_id.base_dir(self.args.output_dir)
            elem_ids = ['sig_%s' % topo_id.file_fmt()] + \
                list(topo.get("control_service", {})) + \
                ['tester_%s' % topo_id.file_fmt()]
            for k in elem_ids:
                disp_id = 'disp_%s' % k
                disp_conf = self._build_disp_conf(disp_id, topo_id)
                write_file(os.path.join(base, '%s.toml' % disp_id), toml.dumps(disp_conf))

    def _build_disp_conf(self, name, topo_id=None):
        prometheus_addr = prom_addr_dispatcher(self.args.docker, topo_id,
                                               self.args.networks, DISP_PROM_PORT, name)
        api_addr = prom_addr_dispatcher(self.args.docker, topo_id,
                                        self.args.networks, DISP_PROM_PORT+700, name)
        srv_addresses = self._build_srv_addresses(self.args.docker, name, topo_id)
        tomlDict = {
            'dispatcher': {
                'id': name,
                'local_udp_forwarding': True,
            },
            'log': self._log_entry(name),
            'metrics': {
                'prometheus': prometheus_addr,
            },
            'features': translate_features(self.args.features),
            'api': {
                'addr': api_addr,
            },
        }
        if len(srv_addresses) > 1:
            tomlDict["dispatcher"]["service_addresses"] = srv_addresses
        return tomlDict

    def _build_srv_addresses(self, docker, name, topo_id):
        srv_addresses = dict()
        if docker:
            if name.startswith("disp_cs"):
                topo = self.args.topo_dicts.get(topo_id)
                cs_addresses = list(topo.get("control_service", {}).values())
                srv_addresses[str(topo_id)+",CS"] = cs_addresses[0]["addr"]
                ds_addresses = list(topo.get("discovery_service", {}).values())
                srv_addresses[str(topo_id)+",DS"] = ds_addresses[0]["addr"]
        else:
            for topo_id, topo in self.args.topo_dicts.items():
                cs_addresses = list(topo.get("control_service", {}).values())
                srv_addresses[str(topo_id)+",CS"] = cs_addresses[0]["addr"]
                ds_addresses = list(topo.get("discovery_service", {}).values())
                srv_addresses[str(topo_id)+",DS"] = ds_addresses[0]["addr"]
        return srv_addresses

    def _tracing_entry(self):
        docker_ip = docker_host(self.args.docker)
        entry = {
            'enabled': True,
            'debug': True,
            'agent': '%s:6831' % docker_ip
        }
        return entry

    def _log_entry(self, name):
        return {
            'console': {
                'level': self.log_level,
            },
        }

    def _metrics_entry(self, infra_elem, base_port):
        a = prom_addr(infra_elem['addr'], base_port)
        return {
            'prometheus': a,
        }

    def _api_entry(self, infra_elem, base_port):
        a = prom_addr(infra_elem['addr'], base_port)
        return {
            'addr': a,
        }
