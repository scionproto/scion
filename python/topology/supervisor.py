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
:mod:`supervisor` --- SCION topology supervisor generator
=============================================
"""
# Stdlib
import configparser
import getpass
import os
from io import StringIO
from string import Template

# SCION
from lib.app.sciond import get_default_sciond_path
from lib.defines import SCIOND_API_SOCKDIR
from lib.packet.scion_addr import ISD_AS
from lib.util import read_file, write_file
from topology.common import _prom_addr_br, _prom_addr_infra, COMMON_DIR

SUPERVISOR_CONF = 'supervisord.conf'


class SupervisorGenerator(object):
    def __init__(self, out_dir, topo_dicts, mininet, cs, sd, ps):
        self.out_dir = out_dir
        self.topo_dicts = topo_dicts
        self.mininet = mininet
        self.cs = cs
        self.sd = sd
        self.ps = ps

    def generate(self):
        self._write_dispatcher_conf()
        for topo_id, topo in self.topo_dicts.items():
            base = topo_id.base_dir(self.out_dir)
            entries = self._as_conf(topo, base)
            self._write_as_conf(topo_id, entries)

    def _as_conf(self, topo, base):
        entries = []
        entries.extend(self._br_entries(topo, "bin/border", base))
        entries.extend(self._bs_entries(topo, base))
        entries.extend(self._cs_entries(topo, base))
        entries.extend(self._ps_entries(topo, base))
        return entries

    def _std_entries(self, topo, topo_key, cmd, base):
        entries = []
        for elem_id, elem in topo.get(topo_key, {}).items():
            conf_dir = os.path.join(base, elem_id)
            entries.append((elem_id, [cmd, "--prom", _prom_addr_infra(elem),
                                      "--sciond_path",
                                      get_default_sciond_path(ISD_AS(topo["ISD_AS"])),
                                      elem_id, conf_dir]))
        return entries

    def _br_entries(self, topo, cmd, base):
        entries = []
        for k, v in topo.get("BorderRouters", {}).items():
            conf_dir = os.path.join(base, k)
            entries.append((k, [cmd, "-id=%s" % k, "-confd=%s" % conf_dir,
                                "-prom=%s" % _prom_addr_br(v)]))
        return entries

    def _bs_entries(self, topo, base):
        return self._std_entries(topo, "BeaconService", "python/bin/beacon_server", base)

    def _cs_entries(self, topo, base):
        if self.cs == "py":
            return self._std_entries(topo, "CertificateService", "python/bin/cert_server", base)
        entries = []
        for k, v in topo.get("CertificateService", {}).items():
            # only a single Go-CS per AS is currently supported
            if k.endswith("-1"):
                conf_dir = os.path.join(base, k)
                entries.append((k, ["bin/cert_srv", "-id=%s" % k, "-confd=%s" % conf_dir,
                                    "-prom=%s" % _prom_addr_infra(v), "-sciond",
                                    get_default_sciond_path(ISD_AS(topo["ISD_AS"]))]))
        return entries

    def _ps_entries(self, topo, base):
        if self.ps == "py":
            return self._std_entries(topo, "PathService", "python/bin/path_server", base)
        entries = []
        for k, v in topo.get("PathService", {}).items():
            # only a single Go-PS per AS is currently supported
            if k.endswith("-1"):
                conf = os.path.join(base, k, "psconfig.toml")
                entries.append((k, ["bin/path_srv", "-config", conf]))
        return entries

    def _sciond_entry(self, name, conf_dir):
        path = self._sciond_path(name)
        if self.sd == "py":
            return self._common_entry(
                name, ["python/bin/sciond", "--api-addr", path, name, conf_dir])
        return self._common_entry(
                name, ["bin/sciond", "-config", os.path.join(conf_dir, "sciond.toml")])

    def _sciond_path(self, name):
        return os.path.join(SCIOND_API_SOCKDIR, "%s.sock" % name)

    def _write_as_conf(self, topo_id, entries):
        config = configparser.ConfigParser(interpolation=None)
        names = []
        base = topo_id.base_dir(self.out_dir)
        for elem, entry in sorted(entries, key=lambda x: x[0]):
            names.append(elem)
            elem_dir = os.path.join(base, elem)
            self._write_elem_conf(elem, entry, elem_dir, topo_id)
            if self.mininet:
                self._write_elem_mininet_conf(elem, elem_dir)
        # Mininet runs sciond per element, and not at an AS level.
        if not self.mininet:
            sd_name = "sd%s" % topo_id.file_fmt()
            names.append(sd_name)
            conf_dir = os.path.join(base, COMMON_DIR)
            config["program:%s" % sd_name] = self._sciond_entry(
                sd_name, conf_dir)
        config["group:as%s" % topo_id.file_fmt()] = {"programs": ",".join(names)}
        text = StringIO()
        config.write(text)
        conf_path = os.path.join(topo_id.base_dir(self.out_dir), SUPERVISOR_CONF)
        write_file(conf_path, text.getvalue())

    def _write_elem_conf(self, elem, entry, elem_dir, topo_id=None):
        config = configparser.ConfigParser(interpolation=None)
        prog = self._common_entry(elem, entry, elem_dir)
        self._write_zlog_cfg(os.path.basename(entry[0]), elem, elem_dir)
        if self.mininet and not elem.startswith("br"):
            # Start a dispatcher for every non-BR element under mininet.
            prog['environment'] += ',DISPATCHER_ID="%s"' % elem
            dp_name = "dp-" + elem
            dp = self._common_entry(dp_name, ["bin/dispatcher"], elem_dir)
            dp['environment'] += ',DISPATCHER_ID="%s"' % elem
            config["program:%s" % dp_name] = dp
            self._write_zlog_cfg("dispatcher", dp_name, elem_dir)
        if elem.startswith("cs"):
            if self.mininet:
                # Start a sciond for every CS element under mininet.
                sd_name = "sd-" + elem
                config["program:%s" % sd_name] = self._sciond_entry(
                    sd_name, elem_dir)
        if elem.startswith("br"):
            prog['environment'] += ',GODEBUG="cgocheck=0"'
        config["program:%s" % elem] = prog
        text = StringIO()
        config.write(text)
        write_file(os.path.join(elem_dir, SUPERVISOR_CONF), text.getvalue())

    def _write_elem_mininet_conf(self, elem, elem_dir):
        tmpl = Template(read_file("python/mininet/supervisord.conf"))
        mn_conf_path = os.path.join(self.out_dir, "mininet", "%s.conf" % elem)
        rel_conf_path = os.path.relpath(
            os.path.join(elem_dir, SUPERVISOR_CONF),
            os.path.join(self.out_dir, "mininet")
        )
        write_file(mn_conf_path,
                   tmpl.substitute(elem=elem, conf_path=rel_conf_path,
                                   user=getpass.getuser()))

    def _write_zlog_cfg(self, name, elem, elem_dir):
        tmpl = Template(read_file("topology/zlog.tmpl"))
        cfg = os.path.join(elem_dir, "%s.zlog.conf" % elem)
        write_file(cfg, tmpl.substitute(name=name, elem=elem))

    def _write_dispatcher_conf(self):
        elem = "dispatcher"
        elem_dir = os.path.join(self.out_dir, elem)
        self._write_elem_conf(elem, ["bin/dispatcher"], elem_dir)

    def _common_entry(self, name, cmd_args, elem_dir=None):
        entry = {
            'autostart': 'false' if self.mininet else 'false',
            'autorestart': 'false',
            'environment': 'PYTHONPATH=python/:.,TZ=UTC',
            'stdout_logfile': "NONE",
            'stderr_logfile': "NONE",
            'startretries': 0,
            'startsecs': 5,
            'priority': 100,
            'command': self._mk_cmd(name, cmd_args),
        }
        if elem_dir:
            zlog = os.path.join(elem_dir, "%s.zlog.conf" % name)
            entry['environment'] += ',ZLOG_CFG="%s"' % zlog
        if name == "dispatcher":
            entry['startsecs'] = 1
            entry['priority'] = 50
        if self.mininet:
            entry['autostart'] = 'true'
        return entry

    def _mk_cmd(self, name, cmd_args):
        return "bash -c 'exec %s &>logs/%s.OUT'" % (
            " ".join(['"%s"' % arg for arg in cmd_args]), name)
