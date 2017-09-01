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
:mod:`cfg_recs` --- Hidden Path Config records
==============================================
"""
# External
import capnp  # noqa

# SCION
import proto.hidden_path_mgmt_capnp as P
from lib.packet.hidden_path_mgmt.config import HiddenPathConfig
from lib.packet.hidden_path_mgmt.base import HiddenPathMgmtPayloadBase
from lib.types import HiddenPathConfigType as CFG


class HiddenPathConfigRecords(HiddenPathMgmtPayloadBase):  # pragma: no cover
    """
    Hidden Path Config Record class used for sending list of hidden path configs.
    """
    P_CLS = P.CfgRecs

    @classmethod
    def from_values(cls, hp_cfgs, timestamp, signature):
        """
        :param hp_cfgs: list of hp_cfg
        :param timestamp: time the payload created
        :param signature: sigrnature of creator
        """
        p = cls.P_CLS.new_message()
        p.init("hpCfgs", len(hp_cfgs))
        for i, hp_cfg in enumerate(hp_cfgs):
            p.hpCfgs[i] = hp_cfg.p
        return cls(p, timestamp, signature)

    def hp_cfg(self, idx):
        return HiddenPathConfig(self.p.hpCfgs[idx])

    def iter_hp_cfgs(self, start=0):
        for i in range(start, len(self.p.hpCfgs)):
            yield self.hp_cfg(i)

    def num_cfgs(self):
        return len(self.p.hpCfgs)


class HiddenPathConfigRecordsReply(HiddenPathConfigRecords):
    NAME = "HiddenPathConfigRecordsReply"
    PAYLOAD_TYPE = CFG.REPLY


class HiddenPathConfigRecordsReg(HiddenPathConfigRecords):
    NAME = "HiddenPathConfigRecordsReg"
    PAYLOAD_TYPE = CFG.REG
