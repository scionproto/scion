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
        config = configparser.ConfigParser(interpolation=None)

        for topo_id, topo in self.args.topo_dicts.items():
            self._add_as_config(config, topo_id, topo)
        self._add_dispatcher(config)

        self._write_config(config, os.path.join(self.args.output_dir, SUPERVISOR_CONF))

    def _add_as_config(self, config, topo_id, topo):
        entries = self._as_entries(topo_id, topo)
        for elem, entry in sorted(entries):
            self._add_prog(config, elem, entry)
        config["group:as%s" % topo_id.file_fmt()] = {
            "programs": ",".join(name for name, _ in sorted(entries))
        }

    def _as_entries(self, topo_id, topo):
        base = topo_id.base_dir(self.args.output_dir)
        entries = []
        entries.extend(self._br_entries(topo, "bin/posix-router", base))
        entries.extend(self._control_service_entries(topo, base))
        entries.append(self._sciond_entry(topo_id, base))
        return entries

    def _br_entries(self, topo, cmd, base):
        entries = []
        for k, v in topo.get("border_routers", {}).items():
            conf = os.path.join(base, f"{k}.toml")
            prog = self._common_entry(k, [cmd, "--config", conf])
            prog['environment'] += ',GODEBUG="cgocheck=0"'
            entries.append((k, prog))
        return entries

    def _control_service_entries(self, topo, base):
        entries = []
        for k, v in topo.get("control_service", {}).items():
            # only a single control service instance per AS is currently supported
            if k.endswith("-1"):
                conf = os.path.join(base, f"{k}.toml")
                prog = self._common_entry(k, ["bin/cs", "--config", conf])
                entries.append((k, prog))
        return entries

    def _sciond_entry(self, topo_id, conf_dir):
        sd_name = "sd%s" % topo_id.file_fmt()
        cmd_args = ["bin/sciond", "--config", os.path.join(conf_dir, SD_CONFIG_NAME)]
        return (sd_name, self._common_entry(sd_name, cmd_args))

    def _add_dispatcher(self, config):
        name, entry = self._dispatcher_entry()
        self._add_prog(config, name, entry)

    def _dispatcher_entry(self):
        name = "dispatcher"
        conf_dir = os.path.join(self.args.output_dir, name)
        cmd_args = ["bin/dispatcher", "--config", os.path.join(conf_dir, DISP_CONFIG_NAME)]
        return (name, self._common_entry(name, cmd_args))

    def _add_prog(self, config, name, entry):
        config["program:%s" % name] = entry

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

    def _write_config(self, config, path):
        text = StringIO()
        config.write(text)
        write_file(path, text.getvalue())
