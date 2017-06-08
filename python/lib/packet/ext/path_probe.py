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
:mod:`path_probe` --- path_probe extension header
=========================================================
"""
# Stdlib
import struct

# SCION
from lib.packet.ext_hdr import EndToEndExtension
from lib.types import ExtEndToEndType
from lib.util import Raw


class PathProbeExt(EndToEndExtension):
    """
    Packets with this extension act as probe packets to determine whether a
    path that has previously failed is back up.
    An extension with the IS_ACK field set to 1 and PROBE_ID matching the
    value in the original probe packet confirms the path is alive.
    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx | IS_ACK |              PROBE_ID             |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    """
    NAME = "PathProbe"
    EXT_TYPE = ExtEndToEndType.PATH_PROBE
    LEN = 5

    def __init__(self, raw=None):
        """
        :param bytes raw: Raw data containing IS_ACK and PROBE_ID
        """
        self.is_ack = False
        self.probe_id = 0
        super().__init__(raw)

    def _parse(self, raw):
        """
        Parse payload to extract values

        :param bytes raw: Raw payload
        """
        super()._parse(raw)
        data = Raw(raw, self.NAME, self.LEN)
        self.is_ack = bool(data.pop(1))
        self.probe_id = struct.unpack("!I", data.pop(4))[0]

    @classmethod
    def from_values(cls, is_ack, probe_id):  # pragma: no cover
        """
        Create an instance of the class PathProbe from the provided values

        :param bool is_ack: True if this packet is an ACK of a previous probe
        :param int probe_id: ID value to use for this probe packet
        """
        inst = cls()
        inst.is_ack = is_ack
        inst.probe_id = probe_id
        return inst

    def pack(self):
        """
        Pack into byte string
        """
        raw = struct.pack("!BI", self.is_ack, self.probe_id)
        self._check_len(raw)
        return raw

    def __str__(self):
        """
        Return string representation
        """
        return "%s(%sB): ACK: %s Probe ID: %s" % (
            self.NAME, len(self), self.is_ack, self.probe_id)
