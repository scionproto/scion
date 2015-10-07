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
from lib.packet.ext_hdr import HopByHopExtension, HopByHopType
from lib.packet.scion_addr import ISD_AD
from lib.util import Raw, SCIONTime


class TracerouteExt(HopByHopExtension):
    """
    0          8         16       24        32            48               64
    | next hdr | hdr len |  0x00  | hops_no |         (padding)            |
    |    ISD_0      |          AD_0         |    IFID_0   |   Timestamp_0  |
    |    ISD_1      |          AD_1         |    IFID_1   |   Timestamp_1  |
                                    ...
    |                     (padding)  or HOP info                           |
    """
    NAME = "TracerouteExt"
    EXT_TYPE = HopByHopType.TRACEROUTE
    PADDING_LEN = 4
    HOP_LEN = HopByHopExtension.LINE_LEN  # Size of every hop information.

    def __init__(self, raw=None):
        """
        Initialize an instance of the class TracerouteExt

        :param raw:
        :type raw:
        """
        super().__init__()
        self.hops = []
        if raw is not None:
            self._parse(raw)

    @classmethod
    def from_values(cls, max_hops_no):
        """
        Construct extension with allocated space for `max_hops_no`.
        """
        inst = TracerouteExt()
        inst._init_size(max_hops_no)
        inst.update()
        return inst

    def _parse(self, raw):
        """
        Parse payload to extract hop informations.
        """
        super()._parse(raw)
        hops_no = self._raw[0]
        data = Raw(self._raw, self.NAME,
                   self.PADDING_LEN + hops_no * self.HOP_LEN, min_=True)
        # Drop hops count and padding from the first row.
        data.pop(1 + self.PADDING_LEN)
        for _ in range(hops_no):
            isd, ad = ISD_AD.from_raw(data.pop(ISD_AD.LEN))  # 4 bytes
            if_id, timestamp = struct.unpack("!HH", data.pop(self.HOP_LEN -
                                                             ISD_AD.LEN))
            self.append_hop(isd, ad, if_id, timestamp)

    def pack(self):
        self.update()
        return self._raw

    def update(self):
        packed = []
        packed.append(struct.pack("!B", len(self.hops)))
        packed.append(bytes(self.PADDING_LEN))
        for isd, ad, if_id, timestamp in self.hops:
            packed.append(ISD_AD(isd, ad).pack())
            packed.append(struct.pack("!HH", if_id, timestamp))
        # Compute and set padding for the rest of the payload.
        pad_hops = self._hdr_len - len(self.hops)
        packed.append(bytes(pad_hops * self.HOP_LEN))
        self._set_payload(b"".join(packed))

    def append_hop(self, isd, ad, if_id, timestamp):
        """
        Append hop's information as a new field in the extension.
        """
        # Check whether
        assert len(self.hops) < self._hdr_len
        self.hops.append((isd, ad, if_id, timestamp))
        self.update()

    def __str__(self):
        """

        :returns:
        :rtype:
        """
        tmp = ["%s(%dB):" % (self.NAME, len(self))]
        tmp.append("  hops:%d" % len(self.hops))
        for hop in self.hops:
            tmp.append("    ISD:%d AD:%d IFID:%d TS:%d" % hop)
        return "\n".join(tmp)


def traceroute_ext_handler(**kwargs):
    """
    Handler for Traceroute extension.
    """
    # Operate on passed extension using router's interface and topology
    ext = kwargs['ext']
    topo = kwargs['topo']
    iface = kwargs['iface']
    ts = int(SCIONTime.get_time() * 1000) % 2**16  # Truncate milliseconds to 2B
    # Append an information about hop
    ext.append_hop(topo.isd_id, topo.ad_id, iface.if_id, ts)
