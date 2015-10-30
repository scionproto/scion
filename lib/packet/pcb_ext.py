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
from lib.packet.packet_base import HeaderBase
from lib.types import TypeBase


class BeaconExtType(TypeBase):
    """
    Constants for two types of beacon extensions.
    """
    MTU = 0


class BeaconExtension(HeaderBase):
    """
    Base class for beacon extensions.
    """
    EXT_TYPE = None
    EXT_TYPE_STR = None
    LEN = None


class MTUExtension(BeaconExtension):  # pragma: no cover
    """
    0        8        16
    |       MTU        |
    """
    EXT_TYPE = BeaconExtType.MTU
    LEN = 2

    def __init__(self, raw=None):
        """
        Initialize an instance of the class MTUExtension

        :param raw:
        :type raw:
        """
        self.mtu = None
        super().__init__(raw)

    @classmethod
    def from_values(cls, mtu):
        """
        Construct extension with `mtu` value.
        """
        inst = cls()
        inst.mtu = mtu
        return inst

    def _parse(self, raw):
        self.mtu = struct.unpack("!H", raw)[0]

    def pack(self):
        return struct.pack("!H", self.mtu)

    def __len__(self):
        return self.LEN

    def __str__(self):
        return "MTU Ext(%dB): MTU is %dB" % (len(self), self.mtu)
