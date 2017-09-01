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
import proto.hp_mgmt_capnp as P
from lib.errors import SCIONSigVerError
from lib.packet.hp_mgmt.config import HiddenPathConfig
from lib.packet.hp_mgmt.base import HiddenPathMgmtPayloadBase
from lib.types import HiddenPathConfigType as CFG


class HiddenPathConfigRecords(HiddenPathMgmtPayloadBase):  # pragma: no cover
    """
    Hidden Path Config Record class used for sending list of hidden path configs.
    """
    P_CLS = P.HPCfgRecs
    VER = len(P_CLS.schema.fields) - 1

    @classmethod
    def from_values(cls, hp_cfgs, timestamp):
        """
        :param hp_cfgs: list of hidden path configs
        :param timestamp: time the payload created
        """
        p = cls.P_CLS.new_message()
        p.init("hpCfgs", len(hp_cfgs))
        for i, hp_cfg in enumerate(hp_cfgs):
            p.hpCfgs[i] = hp_cfg.p
        return cls(p, timestamp)

    def hp_cfg(self, idx):
        return HiddenPathConfig(self.p.hpCfgs[idx])

    def iter_hp_cfgs(self, start=0):
        for i in range(start, len(self.p.hpCfgs)):
            yield self.hp_cfg(i)

    def num_cfgs(self):
        return len(self.p.hpCfgs)

    def sig_pack(self):
        """
        Pack for signing version 0 (defined by highest field number).
        """
        if self.VER != 0:
            raise SCIONSigVerError("HiddenPathConfigRecords.sig_pack cannot support version %s",
                                   self.VER)
        b = []
        for hp_cfg in self.iter_hp_cfgs():
            b.append(hp_cfg.sig_pack4())
        return b"".join(b)


class HiddenPathConfigRecordsReply(HiddenPathConfigRecords):
    NAME = "HiddenPathConfigRecordsReply"
    PAYLOAD_TYPE = CFG.REPLY


class HiddenPathConfigRecordsReg(HiddenPathConfigRecords):
    NAME = "HiddenPathConfigRecordsReg"
    PAYLOAD_TYPE = CFG.REG
