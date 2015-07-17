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
===========================================
"""
# Stdlib
import struct
import time

# SCION
from lib.packet.ext_hdr import ExtensionHeader
from lib.packet.scion_addr import ISD_AD


class TracerouteExt(ExtensionHeader):
    """
    0          8         16           32            48               64
    | next hdr | hdr len |               (padding)                   |
    |    ISD_0      |      AD_0       |    IFID_0   |   Timestamp_0  |
    |    ISD_1      |      AD_1       |    IFID_1   |   Timestamp_1  |
    ...
    """
    TYPE = 221  # Extension header type

    def __init__(self, raw=None):
        """
        Initialize an instance of the class TracerouteExt

        :param raw:
        :type raw:
        """
        self.hops = []
        ExtensionHeader.__init__(self)
        if raw is not None:
            # Parse metadata and payload
            self.parse(raw)
            # Now parse payload
            self.parse_payload()

    def parse_payload(self):
        """

        """
        # Drop padding from the first row
        payload = self.payload[6:]
        while payload:
            isd, ad = ISD_AD.from_raw(payload[:ISD_AD.LEN])  # 4 bytes
            if_id, timestamp = struct.unpack("!HH", payload[ISD_AD.LEN:8])
            self.hops.append((isd, ad, if_id, timestamp))
            payload = payload[8:]

    def append_hop(self, isd, ad, if_id, timestamp):
        """

        """
        self.hops.append((isd, ad, if_id, timestamp))
        self._hdr_len += 1  # Increase by 8 bytes.

    def pack(self):
        """


        :returns:
        :rtype:
        """
        hops_packed = [b"\x00" * 6]  # Padding.
        for hop in self.hops:
            tmp = ISD_AD(hop[0], hop[1]).pack()
            tmp += struct.pack("!HH", hop[2], hop[3])
            hops_packed.append(tmp)
        self.payload = b"".join(hops_packed)
        return ExtensionHeader.pack(self)

    def __str__(self):
        """


        :returns:
        :rtype:
        """
        ret_str = "[Traceroute Ext - start]\n"
        ret_str += "  [next_hdr:%d, len:%d]\n" % (self.next_hdr, len(self))
        for hops in self.hops:
            ret_str += "    ISD:%d AD:%d IFID:%d TS:%d\n" % hops
        ret_str += "[Traceroute Ext - end]"
        return ret_str


def traceroute_ext_handler(**kwargs):
    """
    Handler for Traceroute extension.
    """
    # Operate on passed extension using router's interface and topology
    ext = kwargs['ext']
    topo = kwargs['topo']
    iface = kwargs['iface']
    ts = int(time.time() * 1000) % 2**16  # Truncate milliseconds to 2 bytes
    ext.append_hop(topo.isd_id, topo.ad_id, iface.if_id, ts)
