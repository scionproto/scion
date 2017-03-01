# Copyright 2016 ETH Zurich
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
:mod:`sof` --- SIBRA Opaque Field
=================================
"""
# Stdlib
import struct

# SCION
from lib.crypto.symcrypto import mac
from lib.defines import (
    SIBRA_STEADY_ID_LEN,
    SIBRA_EPHEMERAL_ID_LEN,
)
from lib.sibra.ext.info import ResvInfoBase
from lib.packet.packet_base import Serializable
from lib.util import Raw, hex_str


class SibraOpaqueField(Serializable):
    """
    SIBRA Opqaue Field. This is used for routing SIBRA packets. It describes the
    ingress/egress interfaces, and has a MAC to authenticate that it was issued
    for this reservation.

     0B       1        2        3        4        5        6        7
     +--------+--------+--------+--------+--------+--------+--------+--------+
     | Ingress IF      | Egress IF       | MAC(IFs, res info, pathID, prev)  |
     +--------+--------+--------+--------+--------+--------+--------+--------+
    """
    NAME = "SibraOpaqueField"
    MAC_LEN = 4
    IF_LEN = 2
    LEN = IF_LEN * 2 + MAC_LEN
    # Steady + ephemeral path:
    MAX_PATH_IDS_LEN = SIBRA_EPHEMERAL_ID_LEN + 3 * SIBRA_STEADY_ID_LEN
    MAC_DATA_LEN = IF_LEN * 2 + ResvInfoBase.LEN + MAX_PATH_IDS_LEN + LEN
    MAC_BLOCK_SIZE = 16
    MAC_BLOCK_PADDING = MAC_BLOCK_SIZE - (MAC_DATA_LEN % MAC_BLOCK_SIZE)

    def __init__(self, raw=None):  # pragma: no cover
        self.ingress = None
        self.egress = None
        self.mac = bytes(self.MAC_LEN)
        super().__init__(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.ingress, self.egress = struct.unpack(
            "!HH", data.pop(self.IF_LEN * 2))
        self.mac = data.pop(self.MAC_LEN)

    @classmethod
    def from_values(cls, ingress, egress):  # pragma: no cover
        inst = cls()
        inst.ingress = ingress
        inst.egress = egress
        return inst

    def pack(self):
        raw = []
        raw.append(struct.pack("!HH", self.ingress, self.egress))
        raw.append(self.mac)
        return b"".join(raw)

    def calc_mac(self, info, key, path_ids, prev_raw=None):
        """
        Calculate the MAC based on the reservation info, the relevant path IDs,
        and the previous SOF field if any. The algorithm is a CBC MAC, with
        constant input size.
        """
        raw = []
        raw.append(struct.pack("!HH", self.ingress, self.egress))
        raw.append(info.pack(mac=True))
        ids_len = 0
        for id_ in path_ids:
            ids_len += len(id_)
            raw.append(id_)
        # Pad path IDs with 0's to give constant length
        raw.append(bytes(self.MAX_PATH_IDS_LEN - ids_len))
        raw.append(prev_raw or bytes(self.LEN))
        # Pad to multiple of block size
        raw.append(bytes(self.MAC_BLOCK_PADDING))
        to_mac = b"".join(raw)
        assert len(to_mac) == self.MAC_DATA_LEN + self.MAC_BLOCK_PADDING
        assert len(to_mac) % self.MAC_BLOCK_SIZE == 0
        return mac(key, to_mac)[:self.MAC_LEN]

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        tmp = ["%s(%dB):" % (self.NAME, len(self))]
        tmp.append("Ingress: %s" % self.ingress)
        tmp.append("Egress: %s" % self.egress)
        tmp.append("Mac: %s" % hex_str(self.mac))
        return " ".join(tmp)
