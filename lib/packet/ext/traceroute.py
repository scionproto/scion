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
import time

# SCION
from lib.packet.ext_hdr import HopByHopExtension
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
    EXT_NO = 0
    PADDING_LEN = 4
    HOP_LEN = HopByHopExtension.LINE_LEN  # Size of every hop information.

    def __init__(self, raw=None):
        """
        Initialize an instance of the class TracerouteExt

        :param raw:
        :type raw:
        """
        self.hops = []
        self.hops_no = 0
        super().__init__()
        if raw is not None:
            # Parse metadata and payload
            self.parse(raw)
            # Now parse payload
            self.parse_payload()
        else:
            self.set_payload(b"\x00" * (1 + self.PADDING_LEN))

    @classmethod
    def from_values(cls, max_hops_no):
        """
        Construct extension with allocated space for `max_hops_no`.
        """
        ext = TracerouteExt()
        ext._init_size(max_hops_no)
        return ext

    def parse_payload(self):
        """
        Parse payload to extract hop informations.
        """
        data = Raw(self.payload, "TracerouteExt")
        # Read number of hops.
        self.hops_no = data.pop(1)
        # Drop padding from the first row.
        data.pop(self.PADDING_LEN)
        for _ in range(self.hops_no):
            isd, ad = ISD_AD.from_raw(data.pop(ISD_AD.LEN))  # 4 bytes
            if_id, timestamp = struct.unpack("!HH",
                data.pop(self.HOP_LEN - ISD_AD.LEN))
            self.hops.append((isd, ad, if_id, timestamp))

    def append_hop(self, isd, ad, if_id, timestamp):
        """
        Append hop's information as a new field in the extension.
        """
        # Check whether
        assert self.hops_no < self._hdr_len
        self.hops.append((isd, ad, if_id, timestamp))
        self.hops_no += 1

    def pack(self):
        """
        Pack extension to bytes.

        :returns:
        :rtype:
        """
        hops_packed = [struct.pack("!B", self.hops_no)]
        hops_packed += [b"\x00" * self.PADDING_LEN]  # Padding.
        for isd, ad, if_id, timestamp in self.hops:
            # Pack ISD and AD.
            tmp = ISD_AD(isd, ad).pack()
            # Pack if_id and timestamp.
            tmp += struct.pack("!HH", if_id, timestamp)
            hops_packed.append(tmp)
        # Compute and set padding for the rest of the payload.
        pad_hops = self._hdr_len - self.hops_no
        hops_packed.append(b"\x00" * self.HOP_LEN * pad_hops)
        self.set_payload(b"".join(hops_packed))
        return super().pack()

    def __str__(self):
        """

        :returns:
        :rtype:
        """
        tmp = ["[Traceroute Ext - start]"]
        tmp.append("  [next_hdr:%d ext_no:%d hop:%d len:%d]" %
                   (self.next_hdr, self.EXT_NO, self.hops_no, len(self)))
        for hops in self.hops:
            tmp.append("    ISD:%d AD:%d IFID:%d TS:%d" % hops)
        tmp.append("[Traceroute Ext - end]")
        return "\n".join(tmp)


def traceroute_ext_handler(**kwargs):
    """
    Handler for Traceroute extension.
    """
    # Operate on passed extension using router's interface and topology
    ext = kwargs['ext']
    topo = kwargs['topo']
    iface = kwargs['iface']
    ts = int(SCIONTime.get_time() * 1000) % 2**16  # Truncate milliseconds to 2 bytes
    # Append an information about hop
    ext.append_hop(topo.isd_id, topo.ad_id, iface.if_id, ts)
