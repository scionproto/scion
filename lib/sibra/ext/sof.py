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
# SCION
from lib.crypto.symcrypto import cbcmac
from lib.defines import (
    SIBRA_STEADY_ID_LEN,
    SIBRA_EPHEMERAL_ID_LEN,
)
from lib.packet.opaque_field import HopOpaqueField
from lib.sibra.ext.info import ResvInfoBase


class SibraHopOpaqueField(HopOpaqueField):
    """
    SIBRA Opqaue Field. This is used for routing SIBRA packets. It describes the
    ingress/egress interfaces, and has a MAC to authenticate that it was issued
    for this reservation.

     0B       1        2        3        4        5        6        7
     +--------+--------+--------+--------+--------+--------+--------+--------+
     | Ingress IF      | Egress IF       | MAC(IFs, res info, pathID, prev)  |
     +--------+--------+--------+--------+--------+--------+--------+--------+
    """
    NAME = "SibraHopOpaqueField"
    IFS_LEN = 3
    MAX_PATH_IDS_LEN = SIBRA_EPHEMERAL_ID_LEN + 3 * SIBRA_STEADY_ID_LEN
    MAC_DATA_LEN = (1 + IFS_LEN + ResvInfoBase.LEN + MAX_PATH_IDS_LEN +
                    HopOpaqueField.LEN - 1)
    MAC_BLOCK_SIZE = 16
    MAC_BLOCK_PADDING = MAC_BLOCK_SIZE - (MAC_DATA_LEN % MAC_BLOCK_SIZE)

    @classmethod
    def from_values(cls, ingress, egress):  # pragma: no cover
        inst = cls()
        inst.ingress_if = ingress
        inst.egress_if = egress
        return inst

    def calc_mac(self, info, key, path_ids, prev_raw=None):
        """
        Calculate the MAC based on the reservation info, the relevant path IDs,
        and the previous SOF field if any. The algorithm is a CBC MAC, with
        constant input size.
        """
        raw = []
        # Drop info field (as it changes) and MAC field (empty).
        raw.append(self.pack()[1:-self.MAC_LEN])
        raw.append(info.pack(mac=True))
        ids_len = 0
        for id_ in path_ids:
            ids_len += len(id_)
            raw.append(id_)
        # Pad path IDs with 0's to give constant length
        raw.append(bytes(self.MAX_PATH_IDS_LEN - ids_len))
        if prev_raw:
            # Drop the info field from the previous SOF too.
            raw.append(prev_raw[1:])
        else:
            raw.append(bytes(self.LEN - 1))
        # Pad to multiple of block size
        raw.append(bytes(self.MAC_BLOCK_PADDING))
        to_mac = b"".join(raw)
        assert len(to_mac) == self.MAC_DATA_LEN + self.MAC_BLOCK_PADDING
        assert len(to_mac) % self.MAC_BLOCK_SIZE == 0
        return cbcmac(key, to_mac)[:self.MAC_LEN]
