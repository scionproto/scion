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
:mod:`one_hop_path` --- one_hop_path extension header
=====================================================
"""
# SCION
from lib.packet.ext_hdr import HopByHopExtension
from lib.types import ExtHopByHopType


class OneHopPathExt(HopByHopExtension):
    """
    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx |  0x00     0x00     0x00     0x00     0x00  |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    """
    NAME = "OneHopPath"
    EXT_TYPE = ExtHopByHopType.ONE_HOP_PATH
    LEN = 5
    # Amount of time units a HOF is valid (time unit is EXP_TIME_UNIT).
    HOF_EXP_TIME = 63

    def __init__(self, raw=None):
        super().__init__(raw)

    def _parse(self, raw):
        super()._parse(raw)

    @classmethod
    def from_values(cls):
        return cls()

    def pack(self):
        return b"\x00" * self.LEN

    def __str__(self):
        return "One-hop Path Extension"
