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
import base64
import configparser
import logging
import os
import stat
import sys
from io import StringIO

# External packages
import toml
import yaml

# SCION
from lib.config import Config
from lib.crypto.util import (
    get_master_key,
    get_master_key_file_path,
    MASTER_KEY_0,
    MASTER_KEY_1,
)
from lib.defines import (
    AS_CONF_FILE,
    DEFAULT_MTU,
    DEFAULT6_NETWORK,
    DEFAULT6_PRIV_NETWORK,
    NETWORKS_FILE,
    PATH_POLICY_FILE,
    PRV_NETWORKS_FILE,
)
from lib.path_store import PathPolicy
from lib.packet.scion_addr import ISD_AS
from lib.util import (
    copy_file,
    load_yaml_file,
    write_file,
)
from topology.ca import CAGenArgs, CAGenerator
from topology.cert import CertGenArgs, CertGenerator
from topology.common import (
    ArgsBase,
    srv_iter,
    trust_db_conf_entry,
)
from topology.docker import DockerGenArgs, DockerGenerator
from topology.go import GoGenArgs, GoGenerator
from topology.net import (
    PortGenerator,
    SubnetGenerator,
    DEFAULT_NETWORK,
    DEFAULT_PRIV_NETWORK
)
from topology.prometheus import PrometheusGenArgs, PrometheusGenerator
from topology.supervisor import SupervisorGenArgs, SupervisorGenerator
from topology.topo import TopoGenArgs, TopoGenerator
from topology.zk import ZKGenArgs, ZKGenerator

DEFAULT_TOPOLOGY_FILE = "topology/Default.topo"
DEFAULT_PATH_POLICY_FILE = "topology/PathPolicy.yml"

DEFAULT_CERTIFICATE_SERVER = "go"
DEFAULT_SCIOND = "go"
DEFAULT_PATH_SERVER = "go"
DEFAULT_DISPATCHER = "c"

GENERATE_BIND_ADDRESS = False


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
        self.topo_config = load_yaml_file(self.args.topo_config)
        if self.args.sig and not self.args.docker:
            logging.critical("Cannot use sig without docker!")
            sys.exit(1)
        self.default_mtu = None
        self._read_defaults(self.args.network)
        self.port_gen = PortGenerator()

    def _read_defaults(self, network):
        """
        Configure default network and ZooKeeper setup.
        """
        defaults = self.topo_config.get("defaults", {})
        def_network = network
        if not def_network:
            def_network = defaults.get("subnet")
        if not def_network:
            if self.args.ipv6:
                def_network = DEFAULT6_NETWORK
            else:
                def_network = DEFAULT_NETWORK
        if self.args.ipv6:
            priv_net = DEFAULT6_PRIV_NETWORK
        else:
            priv_net = DEFAULT_PRIV_NETWORK
        self.subnet_gen = SubnetGenerator(def_network, self.args.docker, self.args.in_docker)
        self.prvnet_gen = SubnetGenerator(priv_net, self.args.docker, self.args.in_docker)
        if "zookeepers" not in defaults:
            logging.critical("No zookeeper configured in the topology!")
            sys.exit(1)
        self.default_mtu = defaults.get("mtu", DEFAULT_MTU)

    def generate_all(self):
        """
        Generate all needed files.
        """
        self._ensure_uniq_ases()
        ca_private_key_files, ca_cert_files, ca_certs = self._generate_cas()
        cert_files, trc_files, cust_files = self._generate_certs_trcs()
        topo_dicts, self.networks, prv_networks = self._generate_topology()
        self._generate_with_topo(topo_dicts)
        self._write_ca_files(topo_dicts, ca_private_key_files)
        self._write_ca_files(topo_dicts, ca_cert_files)
        self._write_trust_files(topo_dicts, cert_files)
        self._write_trust_files(topo_dicts, trc_files)
        self._write_cust_files(topo_dicts, cust_files)
        self._write_conf_policies(topo_dicts)
        self._write_master_keys(topo_dicts)
        self._write_networks_conf(self.networks, NETWORKS_FILE)
        if self.args.bind_addr:
            self._write_networks_conf(prv_networks, PRV_NETWORKS_FILE)

    def _ensure_uniq_ases(self):
        seen = set()
        for asStr in self.topo_config["ASes"]:
            ia = ISD_AS(asStr)
            if ia[1] in seen:
                logging.critical("Non-unique AS Id '%s'", ia[1])
                sys.exit(1)
            seen.add(ia[1])

    def _generate_with_topo(self, topo_dicts):
        self._generate_go(topo_dicts)
        if self.args.docker:
            self._generate_docker(topo_dicts)
        else:
            self._generate_supervisor(topo_dicts)
        self._generate_zk(topo_dicts)
        self._generate_prom_conf(topo_dicts)

    def _generate_cas(self):
        ca_gen = CAGenerator(self._ca_args())
        return ca_gen.generate()

    def _ca_args(self):
        return CAGenArgs(self.args, self.topo_config)

    def _generate_certs_trcs(self):
        certgen = CertGenerator(self._cert_args())
        return certgen.generate()

    def _cert_args(self):
        return CertGenArgs(self.args, self.topo_config)

    def _generate_go(self, topo_dicts):
        args = self._go_args(topo_dicts)
        go_gen = GoGenerator(args)
        go_gen.generate_br()
        if self.args.cert_server == "go":
            go_gen.generate_cs()
        if self.args.sciond == "go":
            go_gen.generate_sciond()
        if self.args.path_server == "go":
            go_gen.generate_ps()
        if self.args.dispatcher == "go":
            go_gen.generate_disp()

    def _go_args(self, topo_dicts):
        return GoGenArgs(self.args, topo_dicts, self.port_gen)

    def _generate_topology(self):
        topo_gen = TopoGenerator(self._topo_args())
        return topo_gen.generate()

    def _topo_args(self):
        return TopoGenArgs(self.args, self.topo_config, self.subnet_gen,
                           self.prvnet_gen, self.default_mtu, self.port_gen)

    def _generate_supervisor(self, topo_dicts):
        args = self._supervisor_args(topo_dicts)
        super_gen = SupervisorGenerator(args)
        super_gen.generate()

    def _supervisor_args(self, topo_dicts):
        return SupervisorGenArgs(self.args, topo_dicts, self.port_gen)

    def _generate_docker(self, topo_dicts):
        args = self._docker_args(topo_dicts)
        docker_gen = DockerGenerator(args)
        docker_gen.generate()

    def _docker_args(self, topo_dicts):
        return DockerGenArgs(self.args, topo_dicts, self.networks, self.port_gen)

    def _generate_zk(self, topo_dicts):
        zk_gen = ZKGenerator(ZKGenArgs(self.args, topo_dicts))
        zk_gen.generate()

    def _generate_prom_conf(self, topo_dicts):
        args = self._prometheus_args(topo_dicts)
        prom_gen = PrometheusGenerator(args)
        prom_gen.generate()

    def _prometheus_args(self, topo_dicts):
        return PrometheusGenArgs(self.args, topo_dicts, self.port_gen)

    def _write_ca_files(self, topo_dicts, ca_files):
        isds = set()
        for topo_id, as_topo in topo_dicts.items():
            isds.add(topo_id[0])
        for isd in isds:
            base = os.path.join(self.args.output_dir, "CAS")
            for path, value in ca_files[int(isd)].items():
                write_file(os.path.join(base, path), value.decode())

    def _write_trust_files(self, topo_dicts, cert_files):
        for topo_id, as_topo, base in srv_iter(
                topo_dicts, self.args.output_dir, common=True):
            for path, value in cert_files[topo_id].items():
                write_file(os.path.join(base, path), value + '\n')

    def _write_cust_files(self, topo_dicts, cust_files):
        cust_pk = {}
        for topo_id, as_topo in topo_dicts.items():
            base = topo_id.base_dir(self.args.output_dir)
            for elem in as_topo["CertificateService"]:
                for path, value in cust_files[topo_id].items():
                    write_file(os.path.join(base, elem, path), value)
                    if self.args.cert_server == 'go':
                        cust_dir_name = os.path.dirname(path)
                        cust_dir = os.path.join(base, elem, cust_dir_name)
                        cust_pk[cust_dir] = elem
        if cust_pk:
            script_name = 'gen/load_custs.sh'
            with open(script_name, 'w') as script:
                script.write('#!/bin/bash\n\n')
                for cust_dir, cs_name in cust_pk.items():
                    conf_entry = trust_db_conf_entry(self.args, cs_name)
                    # If we build the dockerized topology the directory is setup to be reachable
                    # from docker, but the tool runs on the host, so we resolve the bind mount here.
                    conf_entry['Connection'] = conf_entry['Connection'].replace('/share/cache',
                                                                                'gen-cache')
                    script.write('cat > cfg.toml << EOL\n%sEOL\n\n'
                                 % toml.dumps({'TrustDB': conf_entry}))
                    script.write('bin/scion-custpk-load -customers %s -config %s\n' % (cust_dir,
                                                                                       'cfg.toml'))
                script.write('rm cfg.toml\n')
            st = os.stat(script_name)
            os.chmod(script_name, st.st_mode | stat.S_IEXEC)

    def _write_conf_policies(self, topo_dicts):
        """
        Write AS configurations and path policies.
        """
        as_confs = {}
        for topo_id, as_topo, base in srv_iter(
                topo_dicts, self.args.output_dir, common=True):
            as_confs.setdefault(topo_id, yaml.dump(
                self._gen_as_conf(as_topo), default_flow_style=False))
            conf_file = os.path.join(base, AS_CONF_FILE)
            write_file(conf_file, as_confs[topo_id])
            # Confirm that config parses cleanly.
            Config.from_file(conf_file)
            copy_file(self.args.path_policy,
                      os.path.join(base, PATH_POLICY_FILE))
        # Confirm that parser actually works on path policy file
        PathPolicy.from_file(self.args.path_policy)

    def _gen_as_conf(self, as_topo):
        return {
            'RegisterTime': 5,
            'PropagateTime': 5,
            'CertChainVersion': 1,
            # FIXME(kormat): This seems to always be true..:
            'RegisterPath': True if as_topo["PathService"] else False,
            'PathSegmentTTL': self.args.pseg_ttl,
        }

    def _write_master_keys(self, topo_dicts):
        """
        Write AS master keys.
        """
        master_keys = {}
        for topo_id, as_topo, base in srv_iter(
                topo_dicts, self.args.output_dir, common=True):

            master_keys.setdefault(topo_id, self._gen_master_keys())
            write_file(get_master_key_file_path(base, MASTER_KEY_0),
                       base64.b64encode(master_keys[topo_id][0]).decode())
            write_file(get_master_key_file_path(base, MASTER_KEY_1),
                       base64.b64encode(master_keys[topo_id][1]).decode())
            # Confirm that keys parse correctly.
            assert get_master_key(base, MASTER_KEY_0) == master_keys[topo_id][0]
            assert get_master_key(base, MASTER_KEY_1) == master_keys[topo_id][1]

    def _gen_master_keys(self):
        return os.urandom(16), os.urandom(16)

    def _write_networks_conf(self, networks, out_file):
        config = configparser.ConfigParser(interpolation=None)
        for i, net in enumerate(networks):
            sub_conf = {}
            for prog, ip_net in networks[net].items():
                sub_conf[prog] = ip_net.ip
            config[net] = sub_conf
        text = StringIO()
        config.write(text)
        write_file(os.path.join(self.args.output_dir, out_file), text.getvalue())
