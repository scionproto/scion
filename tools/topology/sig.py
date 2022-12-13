# Copyright 2018 ETH Zurich
# Copyright 2019 ETH Zurich, Anapaya Systems
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
import json
import os
# External packages
import toml
# SCION
from topology.util import write_file
from topology.common import (
    ArgsBase,
    json_default,
    sciond_svc_name,
    SD_API_PORT,
    SIG_CONFIG_NAME,
    translate_features,
)
from topology.net import socket_address_str
from topology.prometheus import SIG_PROM_PORT


class SIGGenArgs(ArgsBase):
    def __init__(self, args, dc_conf, bridges, networks):
        """
        :param object args: Contains the passed command line arguments as named attributes.
        :param dict dc_conf: The compose config
        :param dict bridges: The generated bridges from DockerGenerator.
        :param dict networks: The generated networks from DockerGenerator.
        """
        super().__init__(args)
        self.dc_conf = dc_conf
        self.bridges = bridges
        self.networks = networks


class SIGGenerator(object):
    def __init__(self, args):
        """
        :param TesterGenArgs args: Contains the passed command line arguments.
        """
        self.args = args
        self.dc_conf = args.dc_conf
        self.user = '%d:%d' % (os.getuid(), os.getgid())
        self.output_base = os.environ.get('SCION_OUTPUT_BASE', os.getcwd())
        self.prefix = ''

    def generate(self):
        for topo_id, topo in self.args.topo_dicts.items():
            base = os.path.join(self.output_base,
                                topo_id.base_dir(self.args.output_dir))
            self._dispatcher_conf(topo_id, base)
            self._sig_dc_conf(topo_id, base)
            self._sig_toml(topo_id, topo)
            self._sig_json(topo_id)
        return self.dc_conf

    def _dispatcher_conf(self, topo_id, base):
        # Create dispatcher config
        entry = {
            'image':
            'dispatcher',
            'container_name':
            'scion_%sdisp_sig_%s' % (self.prefix, topo_id.file_fmt()),
            'depends_on': {
                'utils_chowner': {
                    'condition': 'service_started'
                },
            },
            'user':
            self.user,
            'networks': {},
            'volumes': [
                self._disp_vol(topo_id),
                '%s:/share/conf:rw' % base,
            ],
            'command':
            ['--config',
             '/share/conf/disp_sig_%s.toml' % topo_id.file_fmt()],
        }

        net = self.args.networks['sig%s' % topo_id.file_fmt()][0]
        ipv = 'ipv4'
        if ipv not in net:
            ipv = 'ipv6'
        entry['networks'][self.args.bridges[net['net']]] = {
            '%s_address' % ipv: str(net[ipv])
        }
        self.dc_conf['services']['scion_disp_sig_%s' %
                                 topo_id.file_fmt()] = entry
        vol_name = 'vol_scion_%sdisp_sig_%s' % (self.prefix,
                                                topo_id.file_fmt())
        self.dc_conf['volumes'][vol_name] = None

    def _sig_dc_conf(self, topo_id, base):
        setup_name = 'scion_sig_setup_%s' % topo_id.file_fmt()
        disp_id = 'scion_disp_sig_%s' % topo_id.file_fmt()
        self.dc_conf['services'][setup_name] = {
            'image': 'tester:latest',
            'depends_on': [disp_id],
            'entrypoint': './sig_setup.sh',
            'privileged': True,
            'network_mode': 'service:%s' % disp_id,
        }
        self.dc_conf['services']['scion_sig_%s' % topo_id.file_fmt()] = {
            'image':
            'posix-gateway:latest',
            'container_name':
            'scion_%ssig_%s' % (self.prefix, topo_id.file_fmt()),
            'depends_on': [
                disp_id,
                sciond_svc_name(topo_id),
                setup_name,
            ],
            'environment': {
                'SCION_EXPERIMENTAL_GATEWAY_PATH_UPDATE_INTERVAL': '1s',
            },
            'cap_add': ['NET_ADMIN'],
            # XXX(matzf): running as root; it _should_ work running as unprivileged user. The
            # gateway is a setcap binary and that should suffice. It does work on Ubuntu,
            # but on the RHEL machines in in CI it simply doesn't. Needs to be investigated & fixed.
            #  'user': self.user,
            'volumes': [
                self._disp_vol(topo_id),
                '/dev/net/tun:/dev/net/tun',
                '%s:/share/conf' % base,
            ],
            'network_mode':
            'service:%s' % disp_id,
            'command': ['--config', '/share/conf/sig.toml'],
        }

    def _sig_json(self, topo_id):
        sig_cfg = {"ConfigVersion": 1, "ASes": {}}
        for t_id, topo in self.args.topo_dicts.items():
            if topo_id == t_id:
                continue
            sig_cfg['ASes'][str(t_id)] = {"Nets": []}
            net = self.args.networks['sig%s' % t_id.file_fmt()][0]
            sig_cfg['ASes'][str(t_id)]['Nets'].append(net['net'])

        cfg = os.path.join(topo_id.base_dir(self.args.output_dir), "sig.json")
        contents_json = json.dumps(sig_cfg, default=json_default, indent=2)
        write_file(cfg, contents_json + '\n')

    def _sig_toml(self, topo_id, topo):
        name = 'sig%s' % topo_id.file_fmt()
        net = self.args.networks[name][0]
        log_level = 'debug'
        ipv = 'ipv4'
        if ipv not in net:
            ipv = 'ipv6'

        sciond_net = self.args.networks["sd" + topo_id.file_fmt()][0]
        ipv = 'ipv4'
        if ipv not in sciond_net:
            ipv = 'ipv6'
        sciond_ip = sciond_net[ipv]

        sig_conf = {
            'gateway': {
                'id': name,
                'traffic_policy_file': 'conf/sig.json',
                'ctrl_addr': str(net[ipv]),
            },
            'sciond_connection': {
                'address': socket_address_str(sciond_ip, SD_API_PORT),
            },
            'log': {
                'console': {
                    'level': log_level,
                }
            },
            'metrics': {
                'prometheus': '0.0.0.0:%s' % SIG_PROM_PORT
            },
            'api': {
                'addr': '0.0.0.0:%s' % (SIG_PROM_PORT+700)
            },
            'features': translate_features(self.args.features),
        }
        path = os.path.join(topo_id.base_dir(self.args.output_dir),
                            SIG_CONFIG_NAME)
        write_file(path, toml.dumps(sig_conf))

    def _disp_vol(self, topo_id):
        return 'vol_scion_%sdisp_sig_%s:/run/shm/dispatcher:rw' % (
            self.prefix, topo_id.file_fmt())
