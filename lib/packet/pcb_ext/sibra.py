# Copyright 2015 ETH Zurich
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
:mod:`sibra` --- Beacon SIBRA extension
=======================================
"""
# Stdlib
import struct

# SCION
from lib.packet.pcb_ext import BeaconExtType, BeaconExtension
from lib.util import Raw


class SibraPcbExt(BeaconExtension):
    """
    SIBRA PCB extension, to attach available steady/ephemeral bandwidth for each
    link on a path segment.
    At a granularity of 1kbps, the steady bandwidth requires 10 bits to
    describe, and ephemeral b/w requires 17 bits. So, we can pack both into a
    32bit value. The top 5 bits are reserved.
    """
    # FIXME(kormat): this needs updating to just show total available bandwidth.
    NAME = "SibraPcbExt"
    EXT_TYPE = BeaconExtType.SIBRA
    LEN = 4
    STEADY_BW_BITS = 10
    EPHEMERAL_BW_BITS = 17

    def __init__(self, raw=None):  # pragma: no cover
        self.s_bw = None
        self.e_bw = None
        super().__init__(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        bw = struct.unpack("!I", data.pop(self.LEN))[0]
        self.s_bw = (bw >> self.EPHEMERAL_BW_BITS) & 0x3ff
        self.e_bw = bw & 0x1ffff

    @classmethod
    def from_values(cls, s_bw, e_bw):  # pragma: no cover
        inst = cls()
        assert s_bw < 2**cls.STEADY_BW_BITS
        assert e_bw < 2**cls.EPHEMERAL_BW_BITS
        inst.s_bw = s_bw
        inst.e_bw = e_bw
        return inst

    def pack(self):
        bw = self.s_bw << self.EPHEMERAL_BW_BITS
        bw += self.e_bw
        return struct.pack("!I", bw)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):  # pragma: no cover
        return "B/W available (kbps): steady: %s ephemeral: %s" % (
            self.s_bw, self.e_bw)
