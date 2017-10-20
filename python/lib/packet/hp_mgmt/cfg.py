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
:mod:`cfg` --- Hidden Path Config request/reply/registration
============================================================
"""
# External
import capnp  # noqa

# SCION
import proto.hp_mgmt_capnp as P
from lib.packet.hp_cfg import HPCfg, HPCfgId
from lib.packet.packet_base import Cerealizable
from lib.errors import SCIONSigVerError
from lib.util import proto_len


class HPCfgReq(Cerealizable):
    NAME = "HPCfgReg"
    P_CLS = P.HPCfgReq
    VER = proto_len(P.HPCfgReq.schema) - 1

    @classmethod
    def from_values(cls, hp_cfg_ids):
        """
        :param hp_cfg_ids: list of hidden path configs
        """
        p = cls.P_CLS.new_message()
        p.init("hpCfgsIds", len(hp_cfg_ids))
        for i, hp_cfg_id in enumerate(hp_cfg_ids):
            p.hpCfgIds[i] = hp_cfg_id.p
        return cls(p)

    def hp_cfg_id(self, idx):
        return HPCfgId(self.p.hpCfgs[idx])

    def iter_hp_cfg_ids(self, start=0):
        for i in range(start, len(self.p.hpCfgIds)):
            yield self.hp_cfg_id(i)

    def sig_pack(self):
        """
        Pack for signing version 0 (defined by highest field number).
        """
        if self.VER != 0:
            raise SCIONSigVerError("HPCfgReq.sig_pack cannot support version %s",
                                   self.VER)
        b = []
        for hp_cfg_id in self.iter_hp_cfg_ids():
            b.append(hp_cfg_id.sig_pack())
        return b"".join(b)

    def short_desc(self):
        return ", ".join([cfg_id.short_desc() for cfg_id in self.iter_hp_cfg_ids()])


class HPCfgRecs(Cerealizable):
    NAME = "HPCfgRecs"
    P_CLS = P.HPCfgRecs
    VER = proto_len(P.HPCfgRecs.schema) - 1

    @classmethod
    def from_values(cls, hp_cfgs):
        """
        :param hp_cfgs: list of hidden path configs
        """
        p = cls.P_CLS.new_message()
        p.init("hpCfgs", len(hp_cfgs))
        for i, hp_cfg in enumerate(hp_cfgs):
            p.hpCfgs[i] = hp_cfg.p
        return cls(p)

    def hp_cfg(self, idx):
        return HPCfg(self.p.hpCfgs[idx])

    def iter_hp_cfgs(self, start=0):
        for i in range(start, len(self.p.hpCfgs)):
            yield self.hp_cfg(i)

    def sig_pack(self):
        """
        Pack for signing version 0 (defined by highest field number).
        """
        if self.VER != 0:
            raise SCIONSigVerError("HPCfgRecs.sig_pack cannot support version %s",
                                   self.VER)
        b = []
        for hp_cfg in self.iter_hp_cfgs():
            b.append(hp_cfg.sig_pack())
        return b"".join(b)

    def short_desc(self):
        desc = []
        for i, cfg in enumerate(self.iter_hp_cfgs()):
            desc.append("%d: %s" % (i, cfg.short_desc()))
        return "\n".join(desc)


class HPCfgReply(HPCfgRecs):
    NAME = "HPCfgReply"


class HPCfgReg(HPCfgRecs):
    NAME = "HPCfgReg"
