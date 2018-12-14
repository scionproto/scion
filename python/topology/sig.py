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
import json
import os
from string import Template
# External packages
import toml
# SCION
from lib.app.sciond import get_default_sciond_path
from lib.packet.scion_addr import ISD_AS
from lib.util import read_file, write_file
from topology.common import (
    ArgsBase,
    DOCKER_USR_VOL,
    json_default,
    remote_nets,
    sciond_svc_name
)
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
        self.user_spec = os.environ.get('SCION_USERSPEC', '$LOGNAME')
        self.output_base = os.environ.get('SCION_OUTPUT_BASE', os.getcwd())
        self.prefix = 'docker_' if self.args.in_docker else ''

    def generate(self):
        for topo_id, topo in self.args.topo_dicts.items():
            base = os.path.join(
                self.output_base, topo_id.base_dir(self.args.output_dir))
            self._dispatcher_conf(topo_id, base)
            self._sig_dc_conf(topo_id, base)
            self._sig_toml(topo_id, topo)
            self._sig_json(topo_id)
        return self.dc_conf

    def _dispatcher_conf(self, topo_id, base):
        # Create dispatcher config
        entry = {
            'image': 'scion_dispatcher',
            'container_name': 'scion_%sdisp_sig_%s' % (self.prefix, topo_id.file_fmt()),
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
                'ZLOG_CFG': '/share/conf/disp_sig.zlog.conf'
            },
            'networks': {},
            'volumes': [
                *DOCKER_USR_VOL,
                self._disp_vol(topo_id),
                '%s:/share/conf:rw' % os.path.join(base, 'dispatcher'),
                self._logs_vol()
            ]
        }

        net = self.args.networks['sig%s' % topo_id.file_fmt()][0]
        entry['networks'][self.args.bridges[net['net']]] = {'ipv4_address': str(net['ipv4'])}
        self.dc_conf['services']['scion_disp_sig_%s' % topo_id.file_fmt()] = entry
        vol_name = 'vol_scion_%sdisp_sig_%s' % (self.prefix, topo_id.file_fmt())
        self.dc_conf['volumes'][vol_name] = None
        # Write log config file
        cfg = "%s/dispatcher/%s.zlog.conf" % (topo_id.base_dir(self.args.output_dir), "disp_sig")
        tmpl = Template(read_file("topology/zlog.tmpl"))
        write_file(cfg, tmpl.substitute(name="dispatcher", elem="disp_sig_%s" % topo_id.file_fmt()))

    def _sig_dc_conf(self, topo_id, base):
        self.dc_conf['services']['scion_sig_%s' % topo_id.file_fmt()] = {
            'image': 'scion_sig_acceptance:latest',
            'container_name': 'scion_%ssig_%s' % (self.prefix, topo_id.file_fmt()),
            'depends_on': [
               'scion_disp_sig_%s' % topo_id.file_fmt(),
               sciond_svc_name(topo_id)
            ],
            'cap_add': ['NET_ADMIN'],
            'privileged': True,
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'volumes': [
                *DOCKER_USR_VOL,
                self._disp_vol(topo_id),
                'vol_scion_%ssciond_%s:/run/shm/sciond:rw' % (self.prefix, topo_id.file_fmt()),
                '/dev/net/tun:/dev/net/tun',
                '%s/sig%s:/share/conf' % (base, topo_id.file_fmt()),
                self._logs_vol()
            ],
            'network_mode': 'service:scion_disp_sig_%s' % topo_id.file_fmt(),
            'command': [remote_nets(self.args.networks, topo_id)]
        }

    def _sig_json(self, topo_id):
        sig_cfg = {"ConfigVersion": 1, "ASes": {}}
        for t_id, topo in self.args.topo_dicts.items():
            if topo_id == t_id:
                continue
            sig_cfg['ASes'][str(t_id)] = {"Nets": [], "Sigs": {}}
            net = self.args.networks['sig%s' % t_id.file_fmt()][0]
            sig_cfg['ASes'][str(t_id)]['Nets'].append(net['net'])
            sig_cfg['ASes'][str(t_id)]['Sigs']['sig'] = {"Addr": str(net['ipv4'])}

        cfg = os.path.join(topo_id.base_dir(self.args.output_dir), 'sig%s' % topo_id.file_fmt(),
                           "cfg.json")
        contents_json = json.dumps(sig_cfg, default=json_default, indent=2)
        write_file(cfg, contents_json + '\n')

    def _sig_toml(self, topo_id, topo):
        name = 'sig%s' % topo_id.file_fmt()
        net = self.args.networks[name][0]
        log_level = 'trace' if self.args.trace else 'debug'
        sig_conf = {
            'sig': {
                'ID': name,
                'SIGConfig': 'conf/cfg.json',
                'IA': str(topo_id),
                'IP': str(net['ipv4']),
            },
            'sd_client': {
                'Path': get_default_sciond_path(ISD_AS(topo["ISD_AS"]))
            },
            'logging': {
                'file': {
                    'Level': log_level,
                    'Path': '/share/logs/%s.log' % name
                },
                'console': {
                    'Level': 'error',
                }
            },
            'metrics': {
                'Prometheus': '0.0.0.0:%s' % SIG_PROM_PORT
            }
        }
        path = os.path.join(topo_id.base_dir(self.args.output_dir), name, "sig.toml")
        write_file(path, toml.dumps(sig_conf))

    def _disp_vol(self, topo_id):
        return 'vol_scion_%sdisp_sig_%s:/run/shm/dispatcher:rw' % (self.prefix, topo_id.file_fmt())

    def _logs_vol(self):
        return self.output_base + '/logs:/share/logs:rw'
