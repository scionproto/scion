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
:mod:`pcb_ext` --- Beacon extensions
====================================
"""
# Stdlib
import struct

# SCION
from lib.packet.ext_hdr import BeaconExtension

# Dictionary of supported extensions
PCB_EXTENSION_MAP = {
    (TracerouteExt.EXT_TYPE): MTUExtension,
}


class MTUExtension(BeaconExtension):
    """
    0          8         16       24        32
    |0x00(type)|0x02 (len)|       MTU        |
    """
    EXT_TYPE = 0
    EXT_TYPE_STR = "MTU"
    MIN_LEN = 4
    SUBHDR_LEN = 2
    MIN_PAYLOAD_LEN = MIN_LEN - SUBHDR_LEN

    def __init__(self, raw=None):
        """
        Initialize an instance of the class MTUExtension

        :param raw:
        :type raw:
        """
        super().__init__()
        self.mtu = None
        if raw is not None:
            self._parse(raw)

    @classmethod
    def from_values(cls, mtu):
        """
        Construct extension with `mtu` value.
        """
        inst = MTUExtension()
        inst.mtu = mtu
        return inst

    def _parse(self, raw):
        """
        Parse payload to extract hop informations.
        """
        self.mtu = struct.unpack("!H", raw)[0]

    def pack(self):
        return struct.pack("!H", self.mtu)

    def __len__(self):
        return self.MIN_PAYLOAD_LEN

    def __str__(self):
        """

        :returns:
        :rtype:
        """
        return "MTU Ext (%dB): MTU is %dB" % (len(self), self.mtu)
