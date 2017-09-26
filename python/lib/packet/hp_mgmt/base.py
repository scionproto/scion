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
:mod:`base` --- Base class for Hidden path packets
==================================================
"""
# External
import capnp  # noqa

# SCION
import proto.hp_mgmt_capnp as P
from lib.crypto.asymcrypto import sign
from lib.packet.packet_base import SCIONPayloadBaseProto
from lib.types import PayloadClass


class HiddenPathMgmtPayloadBase(SCIONPayloadBaseProto):  # pragma: no cover
    PAYLOAD_CLASS = PayloadClass.HPATH
    P_CLS = P.HPMsg
    VER = len(P_CLS.schema.fields) - 1

    def __init__(self, p, timestamp):
        super().__init__(p)
        self.timestamp = timestamp
        self.signature = b""

    def sig_pack2(self):
        b = []
        b.append(self.sig_pack())
        b.append(self.timestamp.to_bytes(8, 'big'))
        return b"".join(b)

    def sign(self, key, set_=True):
        sig = sign(self.sig_pack2(), key)
        if set_:
            self.signature = sig
        return sig

    def _pack_full(self, p):
        wrapper = P.HPMsg.new_message(timestamp=self.timestamp,
                                      signature=self.signature, **{self.PAYLOAD_TYPE: p})
        return super()._pack_full(wrapper)
