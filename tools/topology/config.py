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
:mod:`config` --- SCION topology config generator
=============================================
"""
# Stdlib
import configparser
import json
import logging
import os
import sys
from io import StringIO
from typing import Mapping
import yaml

# SCION
from topology.defines import (
    DEFAULT_MTU,
    DEFAULT6_NETWORK,
    NETWORKS_FILE,
    DEFAULT_DISPATCHED_PORTS,
)
from topology.scion_addr import ISD_AS
from topology.util import write_file
from topology.cert import CertGenArgs, CertGenerator
from topology.common import ArgsBase
from topology.docker import DockerGenArgs, DockerGenerator
from topology.go import GoGenArgs, GoGenerator
from topology.net import (
    NetworkDescription,
    IPNetwork,
    SubnetGenerator,
    DEFAULT_NETWORK,
)
from topology.monitoring import MonitoringGenArgs, MonitoringGenerator
from topology.supervisor import SupervisorGenArgs, SupervisorGenerator
from topology.topo import TopoGenArgs, TopoGenerator

DEFAULT_TOPOLOGY_FILE = "topology/default.topo"

SCIOND_ADDRESSES_FILE = "sciond_addresses.json"


class ConfigGenArgs(ArgsBase):
    pass


class ConfigGenerator(object):
    """
    Configuration and/or topology generator.
    """

    def __init__(self, args):
        """
        Initialize an instance of the class ConfigGenerator.

        :param ConfigGenArgs args: Contains the passed command line arguments.
        """
        self.args = args
        with open(self.args.topo_config) as f:
            self.topo_config = yaml.load(f, Loader=yaml.SafeLoader)
        if self.args.sig and not self.args.docker:
            logging.critical("Cannot use sig without docker!")
            sys.exit(1)
        self.default_mtu = None
        self._read_defaults()

    def _read_defaults(self):
        """
        Configure default network.
        """
        defaults = self.topo_config.get("defaults", {})
        self.subnet_gen4 = SubnetGenerator(self.args.network, self.args.docker) \
            if self.args.network else SubnetGenerator(DEFAULT_NETWORK, self.args.docker)
        self.subnet_gen6 = SubnetGenerator(self.args.network_v6, self.args.docker) \
            if self.args.network_v6 else SubnetGenerator(DEFAULT6_NETWORK, self.args.docker)
        self.default_mtu = defaults.get("mtu", DEFAULT_MTU)
        self.dispatched_ports = defaults.get("dispatched_ports", DEFAULT_DISPATCHED_PORTS)

    def generate_all(self):
        """
        Generate all needed files.
        """
        self._ensure_uniq_ases()
        topo_dicts, self.all_networks = self._generate_topology()
        self.networks = remove_v4_nets(self.all_networks)
        self._generate_with_topo(topo_dicts)
        self._write_networks_conf(self.networks, NETWORKS_FILE)
        self._write_sciond_conf(self.networks, SCIOND_ADDRESSES_FILE)

    def _ensure_uniq_ases(self):
        seen = set()
        for asStr in self.topo_config["ASes"]:
            ia = ISD_AS(asStr)
            if ia.as_str() in seen:
                logging.critical("Non-unique AS Id '%s'", ia.as_str())
                sys.exit(1)
            seen.add(ia.as_str())

    def _generate_with_topo(self, topo_dicts):
        self._generate_go(topo_dicts)
        if self.args.docker:
            self._generate_docker(topo_dicts)
        else:
            self._generate_supervisor(topo_dicts)
        self._generate_monitoring_conf(topo_dicts)
        self._generate_certs_trcs(topo_dicts)

    def _generate_certs_trcs(self, topo_dicts):
        certgen = CertGenerator(self._cert_args())
        certgen.generate(topo_dicts)

    def _cert_args(self):
        return CertGenArgs(self.args, self.topo_config)

    def _generate_go(self, topo_dicts):
        args = self._go_args(topo_dicts)
        go_gen = GoGenerator(args)
        go_gen.generate_br()
        go_gen.generate_sciond()
        go_gen.generate_control_service()
        go_gen.generate_disp()

    def _go_args(self, topo_dicts):
        return GoGenArgs(self.args, self.topo_config, topo_dicts, self.networks)

    def _generate_topology(self):
        topo_gen = TopoGenerator(self._topo_args())
        return topo_gen.generate()

    def _topo_args(self):
        return TopoGenArgs(self.args, self.topo_config, self.subnet_gen4,
                           self.subnet_gen6, self.default_mtu,
                           self.dispatched_ports)

    def _generate_supervisor(self, topo_dicts):
        args = self._supervisor_args(topo_dicts)
        super_gen = SupervisorGenerator(args)
        super_gen.generate()

    def _supervisor_args(self, topo_dicts):
        return SupervisorGenArgs(self.args, topo_dicts)

    def _generate_docker(self, topo_dicts):
        args = self._docker_args(topo_dicts)
        docker_gen = DockerGenerator(args)
        docker_gen.generate()

    def _docker_args(self, topo_dicts):
        return DockerGenArgs(self.args, topo_dicts, self.all_networks)

    def _generate_monitoring_conf(self, topo_dicts):
        args = self._monitoring_args(topo_dicts)
        mon_gen = MonitoringGenerator(args)
        mon_gen.generate()

    def _monitoring_args(self, topo_dicts):
        return MonitoringGenArgs(self.args, topo_dicts, self.networks)

    def _write_ca_files(self, topo_dicts, ca_files):
        isds = set()
        for topo_id, as_topo in topo_dicts.items():
            isds.add(topo_id[0])
        for isd in isds:
            base = os.path.join(self.args.output_dir, "CAS")
            for path, value in ca_files[int(isd)].items():
                write_file(os.path.join(base, path), value.decode())

    def _write_networks_conf(self,
                             networks: Mapping[IPNetwork, NetworkDescription],
                             out_file: str):
        config = configparser.ConfigParser(interpolation=None)
        for net, net_desc in networks.items():
            sub_conf = {}
            for prog, ip_net in net_desc.ip_net.items():
                sub_conf[prog] = str(ip_net.ip)
            config[str(net)] = sub_conf
        text = StringIO()
        config.write(text)
        write_file(os.path.join(self.args.output_dir, out_file), text.getvalue())

    def _write_sciond_conf(self, networks: Mapping[IPNetwork, NetworkDescription], out_file: str):
        d = dict()
        for net_desc in networks.values():
            for prog, ip_net in net_desc.ip_net.items():
                if prog.startswith("sd"):
                    ia = prog[2:].replace("_", ":")
                    d[ia] = str(ip_net.ip)
        with open(os.path.join(self.args.output_dir, out_file), mode="w") as f:
            json.dump(d, f, sort_keys=True, indent=4)


def remove_v4_nets(nets: Mapping[IPNetwork, NetworkDescription]
                   ) -> Mapping[IPNetwork, NetworkDescription]:
    res = {}
    for net, net_desc in nets.items():
        if net_desc.name.endswith('_v4'):
            continue
        res[net] = net_desc
    return res
