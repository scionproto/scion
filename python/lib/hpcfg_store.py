# Copyright 2017 ETH Zurich
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
:mod:`hpcfg_store` --- Hidden path service configuration parser
===============================================================
"""
# Stdlib
from collections import defaultdict
import os
import threading

# SCION
from lib.packet.hp_cfg import HPCfg, HPCfgId
from lib.packet.scion_addr import ISD_AS
from lib.util import load_json_file


class HPCfgPolicy(object):
    def __init__(self, isd_as, conf_file=None):
        self.isd_as = isd_as
        self.conf_file = conf_file
        self.conf_dict = defaultdict()
        self.propagation_time = 5
        self.is_master = False
        self.is_reader = False
        self.is_writer = False
        self.if_ids = []
        if os.path.exists(self.conf_file):
            self._parse_local_conf()
        else:
            self.conf_file = None

    def _parse_local_conf(self):
        self.conf_dict = load_json_file(self.conf_file)
        for set_id, set_info in self.conf_dict.items():
            if (set_info.get("MasterAS", None) and
               self.isd_as == ISD_AS(set_info["MasterAS"])):
                self.is_master = True
            if (set_info.get("HiddenASes", None) and
               str(self.isd_as) in set_info["HiddenASes"]):
                self.is_writer = True
                self.if_ids = set_info["IFID"][str(self.isd_as)]
            if not set_info.get("ClientASes", None):
                self.is_reader = True


class HPCfgStore(object):
    def __init__(self, hpcfg_policy):
        self._hpcfgs = defaultdict(list)
        self._hpcfg_ids = defaultdict(list)
        self._if_ids = defaultdict(list)
        self._hpcfg_lock = threading.Lock()
        self._hpcfgid_lock = threading.Lock()
        self.isd_as = hpcfg_policy.isd_as
        self._parse_local_conf(self.isd_as, hpcfg_policy.conf_dict)

    def _parse_local_conf(self, isd_as, conf_dict):
        for set_id, set_info in conf_dict.items():
            if set_info.get("HiddenASes", None):
                self._init_hpcfg(set_info)
            else:
                self._init_hpcfg_id(set_info)

    def _init_hpcfg(self, set_info):
        master_ia = ISD_AS(set_info["MasterAS"])
        cfg_id = set_info["CfgID"]
        version = set_info["Version"]
        hps_ias = self._get_ias(set_info["PathServers"])
        writer_ias = self._get_ias(set_info["HiddenASes"])
        reader_ias = self._get_ias(set_info["ClientASes"])
        hpcfg_id = HPCfgId.from_values(master_ia, cfg_id)
        if_ids = set_info["IFID"]

        self.add_hpcfg(HPCfg.from_values(hpcfg_id, version, hps_ias, writer_ias, reader_ias))
        self.add_ifids(if_ids, hpcfg_id)

    def _init_hpcfg_id(self, set_info):
        hps_ias = self._get_ias(set_info["PathServers"])
        master_ia = ISD_AS(set_info["MasterAS"])
        cfg_id = set_info["CfgID"]

        self.add_hpcfg_id(hps_ias, HPCfgId.from_values(master_ia, cfg_id))

    def _get_ias(self, ias):
        res = []
        for ia in ias:
            res.append(ISD_AS(ia))
        return res

    def get_hpcfg(self, id, version=None):
        with self._hpcfg_lock:
            if not self._hpcfgs[id]:
                return None
            if version is None:
                _, hpcfg = max(self._hpcfgs[id])
                return hpcfg
            for ver, hpcfg in self._hpcfgs[id]:
                if version == ver:
                    return hpcfg
        return None

    def get_hpcfgs(self):
        res = []
        for id in self._hpcfgs:
            res.append(self.get_hpcfg(id))
        return res

    def get_hpcfg_id(self, id):
        with self._hpcfgid_lock:
            if not self._hpcfg_ids[id]:
                return None
            return self._hpcfg_ids[id]

    def get_hpcfg_ids(self):
        res = []
        for id in self._hpcfg_ids:
            res.append((id, self.get_hpcfg_id(id)))
        return res

    def add_hpcfg(self, hpcfg):
        version = hpcfg.version()
        id = hpcfg.id().__hash__()
        with self._hpcfg_lock:
            for ver, _ in self._hpcfgs[id]:
                if version == ver:
                    return
            self._hpcfgs[id].append((version, hpcfg))

    def add_hpcfg_id(self, hps_ias, hpcfg_id):
        id = hpcfg_id
        with self._hpcfgid_lock:
            current_hps = self._hpcfg_ids[id]
            for hps_ia in hps_ias:
                if hps_ia not in current_hps:
                    self._hpcfg_ids[id].append(hps_ia)

    def add_ifids(self, ifid_dict, hpcfg_id):
        for isd_as, intfs in ifid_dict.items():
            if isd_as != str(self.isd_as):
                continue
            for intf in intfs:
                self._if_ids[intf].append(hpcfg_id)

    def is_approved(self, hpcfg_id, reader_ia=None, writer_ia=None):
        id = hpcfg_id.__hash__()
        hpcfg = self.get_hpcfg(id)
        if not hpcfg:
            return None
        if reader_ia and reader_ia in hpcfg.iter_reader_ias():
            if writer_ia:
                if writer_ia in hpcfg.iter_writer_ias():
                    return hpcfg
                else:
                    return None
            return hpcfg
        if writer_ia and (writer_ia == hpcfg_id.master_ia() or
                          writer_ia in hpcfg.iter_hps_ias()):
            return hpcfg
        return None

    def is_hidden_as(self, writer_ia):
        for hpcfg in self.get_hpcfgs():
            if not hpcfg:
                continue
            if writer_ia in hpcfg.iter_writer_ias():
                return hpcfg
        return None

    def get_intf_conf(self, if_id):
        return self._if_ids[if_id]

    def get_hpcfg_from_data(self, reader_ia, writer_ia):
        for hpcfg in self.get_hpcfgs():
            if not hpcfg:
                continue
            if reader_ia in hpcfg.iter_reader_ias() and writer_ia in hpcfg.iter_writer_ias():
                return hpcfg
        return None
