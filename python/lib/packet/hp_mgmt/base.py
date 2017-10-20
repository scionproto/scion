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
:mod:`base` --- Container for hidden path packets
==================================================
"""
# External
import capnp  # noqa

# SCION
import proto.hp_mgmt_capnp as P
from lib.errors import SCIONSigVerError
from lib.crypto.asymcrypto import sign
from lib.packet.hp_mgmt.seg import HPSegReg, HPSegReply, HPSegReq
from lib.packet.hp_mgmt.cfg import HPCfgReg, HPCfgReply, HPCfgReq
from lib.packet.packet_base import CerealBox
from lib.types import HPMgmtType
from lib.util import proto_len


class HPMgmt(CerealBox):  # pragma: no cover
    NAME = "HPMgmt"
    P_CLS = P.HPMgmt
    VER = proto_len(P.HPMgmt.schema) - 1  # Highest number in the capnp schema.
    CLASS_FIELD_MAP = {
        HPCfgReq: HPMgmtType.CFG_REQ,
        HPCfgReply: HPMgmtType.CFG_REPLY,
        HPCfgReg: HPMgmtType.CFG_REG,
        HPSegReq: HPMgmtType.SEG_REQ,
        HPSegReply: HPMgmtType.SEG_REPLY,
        HPSegReg: HPMgmtType.SEG_REG,
    }

    def __init__(self, p, timestamp):
        super().__init__(p)
        self.timestamp = timestamp
        self.signature = b""

    def sig_pack(self):
        """Pack for signing version 7 (defined by highest field number)"""
        if self.VER != 7:
            raise SCIONSigVerError("HPMgmt.sig_pack cannot support version %s",
                                   self.VER)
        b = []
        b.append(self.timestamp.to_bytes(8, 'big'))
        b.append(self.union.sig_pack())
        return b"".join(b)

    def sign(self, key, set_=True):
        sig = sign(self.sig_pack(), key)
        if set_:
            self.signature = sig
        return sig
