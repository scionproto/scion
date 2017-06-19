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
:mod:`traceroute` --- Traceroute extension header and its handler
=================================================================
"""
# Stdlib
import struct

# SCION
from lib.packet.ext_hdr import HopByHopExtension
from lib.packet.scion_addr import ISD_AS
from lib.util import Raw, SCIONTime
from lib.types import ExtHopByHopType


class TracerouteExt(HopByHopExtension):
    """
    0b         8         16       24        32            48               64
    | next hdr | hdr len |  0x00  | hops_no |         (padding)            |
    |    ISD_0      |          AS_0         |    IFID_0   |   Timestamp_0  |
    |    ISD_1      |          AS_1         |    IFID_1   |   Timestamp_1  |
                                    ...
    |                     (padding)  or HOP info                           |
    """
    NAME = "TracerouteExt"
    EXT_TYPE = ExtHopByHopType.TRACEROUTE
    PADDING_LEN = 4
    MIN_LEN = 1 + PADDING_LEN
    HOP_LEN = HopByHopExtension.LINE_LEN  # Size of every hop information.

    def __init__(self, raw=None):  # pragma: no cover
        self.hops = []
        super().__init__(raw)

    def _parse(self, raw):
        """
        Parse payload to extract hop informations.
        """
        hops_no = raw[0]
        data = Raw(raw, self.NAME, self.MIN_LEN + hops_no * self.HOP_LEN,
                   min_=True)
        super()._parse(data)
        # Drop hops no and padding from the first row.
        data.pop(self.MIN_LEN)
        for _ in range(hops_no):
            isd_as = ISD_AS(data.pop(ISD_AS.LEN))  # 4 bytes
            if_id, timestamp = struct.unpack(
                "!HH", data.pop(self.HOP_LEN - ISD_AS.LEN))
            self.append_hop(isd_as, if_id, timestamp)

    @classmethod
    def from_values(cls, max_hops_no):  # pragma: no cover
        """
        Construct extension with allocated space for `max_hops_no`.
        """
        inst = TracerouteExt()
        inst._init_size(max_hops_no)
        return inst

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", len(self.hops)))
        packed.append(bytes(self.PADDING_LEN))
        for isd_as, if_id, timestamp in self.hops:
            packed.append(isd_as.pack())
            packed.append(struct.pack("!HH", if_id, timestamp))
        # Compute and set padding for the rest of the payload.
        pad_hops = self._hdr_len - len(self.hops) - 1
        packed.append(bytes(pad_hops * self.HOP_LEN))
        raw = b"".join(packed)
        self._check_len(raw)
        return raw

    def append_hop(self, isd_as, if_id, timestamp=None):  # pragma: no cover
        """
        Append hop's information as a new field in the extension.
        """
        # Check whether
        assert len(self.hops) < self._hdr_len - 1
        if timestamp is None:
            # Truncate milliseconds to 2B
            timestamp = int(SCIONTime.get_time() * 1000) % 2**16
        self.hops.append((isd_as, if_id, timestamp))

    def __str__(self):
        tmp = ["%s(%sB):" % (self.NAME, len(self))]
        tmp.append("  hops:%s" % len(self.hops))
        for hop in self.hops:
            tmp.append("    ISD-AS: %s IFID: %s TS: %s" % hop)
        return "\n".join(tmp)
