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
:mod:`cfg_req` --- Hidden Path Config request
=============================================
"""
# External
import capnp  # noqa

# SCION
import proto.hidden_path_mgmt_capnp as P
from lib.packet.hidden_path_mgmt.config import HiddenPathConfigId
from lib.packet.hidden_path_mgmt.base import HiddenPathMgmtPayloadBase
from lib.types import HiddenPathConfigType as CFG


class HiddenPathConfigReq(HiddenPathMgmtPayloadBase):  # pragma: no cover
    """Describes a request for hidden path config(s)"""
    NAME = "HiddenPathConfigReq"
    PAYLOAD_TYPE = CFG.REQUEST
    P_CLS = P.CfgReq

    @classmethod
    def from_values(cls, hp_cfg_ids, timestamp, signature):
        p = cls.P_CLS.new_message()
        p.init("hpCfgIds", len(hp_cfg_ids))
        for i, hp_cfg_id in enumerate(hp_cfg_ids):
            p.hpCfgIds[i] = hp_cfg_id.p
        return cls(p, timestamp, signature)

    def hp_cfg_id(self, idx):
        return HiddenPathConfigId(self.p.hpCfgIds[idx])

    def iter_hp_cfg_ids(self, start=0):
        for i in range(start, len(self.p.hpCfgIds)):
            yield self.hp_cfg_id(i)
