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
import os
import shlex
from io import StringIO

# SCION
from python.lib.util import write_file
from python.topology.common import (
    ArgsTopoDicts,
    DISP_CONFIG_NAME,
    FEATURE_HEADER_V2,
    SD_CONFIG_NAME,
)


SUPERVISOR_CONF = 'supervisord.conf'


class SupervisorGenArgs(ArgsTopoDicts):
    pass


class SupervisorGenerator(object):
    def __init__(self, args):
        """
        :param SupervisorGenArgs args: Contains the passed command line arguments and topo dicts.
        """
        self.args = args

    def generate(self):
        self._write_dispatcher_conf()
        for topo_id, topo in self.args.topo_dicts.items():
            base = topo_id.base_dir(self.args.output_dir)
            entries = self._as_conf(topo, base)
            self._write_as_conf(topo_id, entries)

    def _as_conf(self, topo, base):
        entries = []
        if FEATURE_HEADER_V2 in self.args.features:
            entries.extend(self._br_entries(topo, "bin/posix-router", base))
        else:
            entries.extend(self._br_entries(topo, "bin/border", base))
        entries.extend(self._control_service_entries(topo, base))
        return entries

    def _br_entries(self, topo, cmd, base):
        entries = []
        for k, v in topo.get("border_routers", {}).items():
            conf = os.path.join(base, f"{k}.toml")
            entries.append((k, [cmd, "--config", conf]))
        return entries

    def _control_service_entries(self, topo, base):
        entries = []
        for k, v in topo.get("control_service", {}).items():
            # only a single control service instance per AS is currently supported
            if k.endswith("-1"):
                conf = os.path.join(base, f"{k}.toml")
                entries.append((k, ["bin/cs", "--config", conf]))
        return entries

    def _sciond_entry(self, name, conf_dir):
        return self._common_entry(
            name, ["bin/sciond", "--config", os.path.join(conf_dir, SD_CONFIG_NAME)])

    def _write_as_conf(self, topo_id, entries):
        config = configparser.ConfigParser(interpolation=None)
        names = []
        base = topo_id.base_dir(self.args.output_dir)
        for elem, entry in sorted(entries, key=lambda x: x[0]):
            names.append(elem)
            self._write_elem_conf(elem, entry, os.path.join(base, f"supervisord-{elem}.conf"))
        sd_name = "sd%s" % topo_id.file_fmt()
        names.append(sd_name)
        config["program:%s" % sd_name] = self._sciond_entry(sd_name, base)
        config["group:as%s" % topo_id.file_fmt()] = {
            "programs": ",".join(names)}
        text = StringIO()
        config.write(text)
        conf_path = os.path.join(topo_id.base_dir(
            self.args.output_dir), SUPERVISOR_CONF)
        write_file(conf_path, text.getvalue())

    def _write_elem_conf(self, elem, entry, path):
        config = configparser.ConfigParser(interpolation=None)
        prog = self._common_entry(elem, entry)
        if elem.startswith("br"):
            prog['environment'] += ',GODEBUG="cgocheck=0"'
        config["program:%s" % elem] = prog
        text = StringIO()
        config.write(text)
        write_file(path, text.getvalue())

    def _write_dispatcher_conf(self):
        elem = "dispatcher"
        elem_dir = os.path.join(self.args.output_dir, elem)
        config_file_path = os.path.join(elem_dir, DISP_CONFIG_NAME)
        self._write_elem_conf(elem,
                              ["bin/dispatcher", "--config", config_file_path],
                              os.path.join(elem_dir, SUPERVISOR_CONF))

    def _common_entry(self, name, cmd_args):
        entry = {
            'autostart': 'false',
            'autorestart': 'false',
            'environment': 'TZ=UTC',
            'stdout_logfile': f"logs/{name}.log",
            'redirect_stderr': True,
            'startretries': 0,
            'startsecs': 5,
            'priority': 100,
            'command': ' '.join(shlex.quote(a) for a in cmd_args),
        }
        if name == "dispatcher":
            entry['startsecs'] = 1
            entry['priority'] = 50
        return entry
