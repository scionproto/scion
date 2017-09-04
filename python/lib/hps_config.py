# Copyright 2014 ETH Zurich
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
:mod:`hps_config` --- Hidden path service configuration parser
==============================================================
"""
# Stdlib
import os

# SCION
from lib.packet.scion_addr import ISD_AS
from lib.packet.path_mgmt.set_info import PCBSetInfo
from lib.util import load_json_file


class RegConf(object):
    """
    Information for each PCB set.
    """
    def __init__(self, hps_ia, set_ids):
        self.hpsIA = hps_ia
        self.setIDs = set_ids


class InterfaceConf(object):
    """
    The configuration for an interface.
    """
    def __init__(self, if_id, if_dict):
        self.ifID = int(if_id)
        self.regConfs = []
        self._parse_dict(if_dict)

    def _parse_dict(self, if_dict):
        for conf in if_dict:
            self.regConfs.append(RegConf(ISD_AS(conf['HPS']), conf['SetID']))


class HPSProvider(object):
    """
    The Config class parses the configuration file of a hidden AS and
    stores such information for further use.

    :ivar list(InterfaceConf) intfConfs: the configuration for
                                         each interface on border routers.
    :ivar list(PCBSetInfo) setInfos: PCB set information.
    """
    def __init__(self):  # pragma: no cover
        self.intfConfs = []
        self.setInfos = []

    @classmethod
    def from_values(cls, isd_as, config_file):
        if not os.path.exists(config_file):
            return None
        config = cls()
        config.parse_dict(isd_as, load_json_file(config_file))
        if not config.intfConfs:
            return None
        return config

    def parse_dict(self, isd_as, config):
        """
        Parse a configuration file and populate the instance's attributes.
        """
        self._parse_as_conf(isd_as, config)
        self._parse_group_conf(config)

    def _parse_as_conf(self, isd_as, config):
        """
        Hidden AS (provider AS) configuration.
        """
        for as_id, as_dict in config['HiddenASes'].items():
            if isd_as != ISD_AS(as_id):
                continue
            for if_id, if_dict in as_dict.items():
                self.intfConfs.append(InterfaceConf(if_id, if_dict))

    def _parse_group_conf(self, config):
        """
        Authorized AS (client AS) configuration.
        """
        for set_id, set_dict in config['AuthorizedGroups'].items():
            hps = ISD_AS(set_dict['HPS'])
            members = []
            for client in set_dict['Clients']:
                members.append(ISD_AS(client))
            self.setInfos.append(PCBSetInfo.from_values(set_id, hps, members))

    def is_hidden_pcb(self, pcb):
        for if_conf in self.intfConfs:
            if pcb.p.ifID == if_conf.ifID:
                return True
        return False

    def intfConf(self, idx):
        return self.intfConfs[idx]

    def iter_intfConfs(self, start=0):
        for i in range(start, len(self.intfConfs)):
            yield self.intfConf(i)

    def set_info(self, idx):
        return self.setInfos[idx]

    def iter_set_info(self, start=0):
        for i in range(start, len(self.setInfos)):
            yield self.set_info(i)

    def get_intf_conf(self, if_id):
        for intfConf in self.iter_intfConfs():
            if intfConf.ifID == if_id:
                return intfConf
        return None

    def get_intf_confs(self, if_id):
        ret = {}
        for regConf in self.get_intf_conf(if_id).regConfs:
            hpsIA = regConf.hpsIA
            setInfos = []
            for setInfo in self.setInfos:
                if setInfo.set_id() in regConf.setIDs:
                    setInfos.append(setInfo)
            ret[hpsIA] = setInfos
        return ret.items()


class HPSClient(object):
    """
    The Config class parses the configuration file of an authorized AS for
    the hidden path and stores such information for further use.

    :ivar list(PCBSetInfo) setInfos: PCB set information.
    """
    def __init__(self):  # pragma: no cover
        self.setInfos = []

    @classmethod
    def from_values(cls, isd_as, config_file):
        if not os.path.exists(config_file):
            return None
        config = cls()
        config.parse_dict(isd_as, load_json_file(config_file))
        if not config.setInfos:
            return None
        return config

    def parse_dict(self, isd_as, config):
        """
        Parse a configuration file and populate the instance's attributes.
        """
        for set_id, set_dict in config['AuthorizedGroups'].items():
            if str(isd_as) not in set_dict['Clients']:
                continue
            hps = ISD_AS(set_dict['HPS'])
            members = []
            for provider in set_dict['Providers']:
                members.append(ISD_AS(provider))
            self.setInfos.append(PCBSetInfo.from_values(set_id, hps, members))

    def set_info(self, idx):
        return self.setInfos[idx]

    def iter_set_info(self, start=0):
        for i in range(start, len(self.setInfos)):
            yield self.set_info(i)

    def get_set_infos(self, dst_ia):
        ret = []
        for set_info in self.iter_set_info():
            if dst_ia in set_info.iter_member_ias():
                ret.append(set_info)
        return ret
