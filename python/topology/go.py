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
import yaml
from typing import Mapping

# SCION
from python.lib.util import write_file
from python.topology.common import (
    ArgsTopoDicts,
    DISP_CONFIG_NAME,
    docker_host,
    prom_addr,
    prom_addr_dispatcher,
    sciond_ip,
    sciond_name,
    translate_features,
    SD_API_PORT,
    SD_CONFIG_NAME,
    CO_CONFIG_NAME,
)

from python.topology.net import socket_address_str, NetworkDescription, IPNetwork

from python.topology.prometheus import (
    CS_PROM_PORT,
    DEFAULT_BR_PROM_PORT,
    SCIOND_PROM_PORT,
    DISP_PROM_PORT,
    CO_PROM_PORT,
)
from python.topology.topo import DEFAULT_LINK_BW

CS_QUIC_PORT = 30352
CO_QUIC_PORT = 30357


class GoGenArgs(ArgsTopoDicts):
    def __init__(self, args, topo_dicts, networks: Mapping[IPNetwork, NetworkDescription]):
        super().__init__(args, topo_dicts)
        self.networks = networks


class GoGenerator(object):
    def __init__(self, args):
        """
        :param GoGenArgs args: Contains the passed command line arguments and topo dicts.
        """
        self.args = args
        self.log_dir = '/share/logs' if args.docker else 'logs'
        self.db_dir = '/share/cache' if args.docker else 'gen-cache'
        self.certs_dir = '/share/crypto' if args.docker else 'gen-certs'
        self.log_level = 'debug'

    def generate_br(self):
        for topo_id, topo in self.args.topo_dicts.items():
            for k, v in topo.get("border_routers", {}).items():
                base = topo_id.base_dir(self.args.output_dir)
                br_conf = self._build_br_conf(topo_id, topo["isd_as"], base, k, v)
                write_file(os.path.join(base, "%s.toml" % k), toml.dumps(br_conf))

    def _build_br_conf(self, topo_id, ia, base, name, v):
        config_dir = '/share/conf' if self.args.docker else base
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
        }
        return raw_entry

    def generate_control_service(self):
        for topo_id, topo in self.args.topo_dicts.items():
            ca = 'issuing' in topo.get("attributes", [])
            for elem_id, elem in topo.get("control_service", {}).items():
                # only a single Go-BS per AS is currently supported
                if elem_id.endswith("-1"):
                    base = topo_id.base_dir(self.args.output_dir)
                    bs_conf = self._build_control_service_conf(
                        topo_id, topo["isd_as"], base, elem_id, elem, ca)
                    write_file(os.path.join(base, "%s.toml" % elem_id),
                               toml.dumps(bs_conf))

    def _build_control_service_conf(self, topo_id, ia, base, name, infra_elem, ca):
        config_dir = '/share/conf' if self.args.docker else base
        raw_entry = {
            'general': {
                'id': name,
                'config_dir': config_dir,
                'reconnect_to_dispatcher': True,
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
            'features': translate_features(self.args.features),
        }
        if ca:
            raw_entry['renewal_db'] = {
                'connection': os.path.join(self.db_dir, '%s.renewal.db' % name),
            }
        return raw_entry

    def generate_co(self):
        if not self.args.colibri:
            return
        for topo_id, topo in self.args.topo_dicts.items():
            for elem_id, elem in topo.get("colibri_service", {}).items():
                # only a single Go-CO per AS is currently supported
                if elem_id.endswith("-1"):
                    base = topo_id.base_dir(self.args.output_dir)
                    co_conf = self._build_co_conf(topo_id, topo["isd_as"], base, elem_id, elem)
                    write_file(os.path.join(base, elem_id, CO_CONFIG_NAME), toml.dumps(co_conf))
                    traffic_matrix = self._build_co_traffic_matrix(topo_id)
                    write_file(os.path.join(base, elem_id, 'matrix.yml'),
                               yaml.dump(traffic_matrix, default_flow_style=False))
                    rsvps = self._build_co_reservations(topo_id)
                    write_file(os.path.join(base, elem_id, 'reservations.yml'),
                               yaml.dump(rsvps, default_flow_style=False))

    def _build_co_conf(self, topo_id, ia, base, name, infra_elem):
        config_dir = '/share/conf' if self.args.docker else base
        raw_entry = {
            'general': {
                'ID': name,
                'ConfigDir': config_dir,
                'ReconnectToDispatcher': True,
            },
            'log': self._log_entry(name),
            'trust_db': {
                'connection': os.path.join(self.db_dir, '%s.trust.db' % name),
            },
            'tracing': self._tracing_entry(),
            'metrics': self._metrics_entry(infra_elem, CO_PROM_PORT),
            'features': translate_features(self.args.features),
        }
        return raw_entry

    def _build_co_traffic_matrix(self, ia):
        """
        Creates a NxN traffic matrix for colibri with N = len(interfaces)
        """
        topo = self.args.topo_dicts[ia]
        if_ids = {iface for br in topo['border_routers'].values() for iface in br['interfaces']}
        if_ids.add(0)
        bw = int(DEFAULT_LINK_BW / (len(if_ids) - 1))
        traffic_matrix = {}
        for inIfid in if_ids:
            traffic_matrix[inIfid] = {}
            for egIfid in if_ids.difference({inIfid}):
                traffic_matrix[inIfid][egIfid] = bw
        return traffic_matrix

    def _build_co_reservations(self, ia):
        """
        Generates a dictionary of reservations with one entry per core AS (if "ia" is core)
        excluding itself, or a pair (up and down) per core AS in the ISD if "ia" is not core.
        """
        rsvps = {}
        this_as = self.args.topo_dicts[ia]
        if this_as['Core']:
            for dst_ia, topo in self.args.topo_dicts.items():
                if dst_ia != ia and topo['Core']:
                    rsvps['Core-%s' % dst_ia] = self._build_co_reservation(dst_ia, 'Core')
        else:
            for dst_ia, topo in self.args.topo_dicts.items():
                if dst_ia != ia and dst_ia._isd == ia._isd and topo['Core']:
                    # reach this core AS in the same ISD
                    rsvps['Up-%s' % dst_ia] = self._build_co_reservation(dst_ia, 'Up')
                    rsvps['Down-%s' % dst_ia] = self._build_co_reservation(dst_ia, 'Down')
        return rsvps

    def _build_co_reservation(self, dst_ia, path_type):
        start_props = {'L', 'T'}
        end_props = {'L', 'T'}
        if path_type == 'Up':
            start_props.remove('T')
        elif path_type == 'Down':
            end_props.remove('T')
        return {
            'desired_size': 27,
            'ia': str(dst_ia),
            'max_size': 30,
            'min_size': 1,
            'path_predicate': '%s#0' % dst_ia,
            'path_type': path_type,
            'split_cls': 8,
            'end_props': {
                'start': list(start_props),
                'end': list(end_props)
            }
        }

    def generate_sciond(self):
        for topo_id, topo in self.args.topo_dicts.items():
            base = topo_id.base_dir(self.args.output_dir)
            sciond_conf = self._build_sciond_conf(topo_id, topo["isd_as"], base)
            write_file(os.path.join(base, SD_CONFIG_NAME), toml.dumps(sciond_conf))

    def _build_sciond_conf(self, topo_id, ia, base):
        name = sciond_name(topo_id)
        config_dir = '/share/conf' if self.args.docker else base
        ip = sciond_ip(self.args.docker, topo_id, self.args.networks)
        raw_entry = {
            'general': {
                'id': name,
                'config_dir': config_dir,
                'reconnect_to_dispatcher': True,
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
        }
        return raw_entry

    def generate_disp(self):
        if self.args.docker:
            self._gen_disp_docker()
        else:
            elem_dir = os.path.join(self.args.output_dir, "dispatcher")
            config_file_path = os.path.join(elem_dir, DISP_CONFIG_NAME)
            write_file(config_file_path, toml.dumps(self._build_disp_conf("dispatcher")))

    def _gen_disp_docker(self):
        for topo_id, topo in self.args.topo_dicts.items():
            base = topo_id.base_dir(self.args.output_dir)
            elem_ids = ['sig_%s' % topo_id.file_fmt()] + \
                list(topo.get("border_routers", {})) + \
                list(topo.get("control_service", {})) + \
                ['tester_%s' % topo_id.file_fmt()]
            for k in elem_ids:
                disp_id = 'disp_%s' % k
                disp_conf = self._build_disp_conf(disp_id, topo_id)
                write_file(os.path.join(base, '%s.toml' % disp_id), toml.dumps(disp_conf))

    def _build_disp_conf(self, name, topo_id=None):
        prometheus_addr = prom_addr_dispatcher(self.args.docker, topo_id,
                                               self.args.networks, DISP_PROM_PORT, name)
        return {
            'dispatcher': {
                'id': name,
            },
            'log': self._log_entry(name),
            'metrics': {
                'prometheus': prometheus_addr,
            },
            'features': translate_features(self.args.features),
        }

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
