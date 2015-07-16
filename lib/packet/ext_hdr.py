# Copyright 2014 ETH Zurich
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
:mod:`ext_hdr` --- Extension header classes
===========================================
"""
# Stdlib
import logging
import struct

# SCION
from lib.packet.packet_base import HeaderBase
from lib.packet.scion_addr import ISD_AD


class ExtensionHeader(HeaderBase):
    """
    Base class for extension headers.
    For each extension header there should be a subclass of this class (e.g
    StrideExtensionHeader).

    :cvar MIN_LEN:
    :type MIN_LEN: int
    :ivar next_hdr:
    :type next_hdr:
    :ivar _hdr_len:
    :type _hdr_len:
    :ivar parsed:
    :type parsed:
    """
    MIN_LEN = 8

    def __init__(self, raw=None):
        """
        Initialize an instance of the class ExtensionHeader.

        :param raw:
        :type raw:
        :param _hdr_len: encoded length of extension header. The length in
                         bytes is calculated as (next_hdr + 1) * 8.
        :type _hdr_len: int
        :param next_hdr: indication of a next extension header. Must be set
                          by SCIONHeader's pack().
        :type next_hdr: int
        """
        HeaderBase.__init__(self)
        self.next_hdr = 0
        self._hdr_len = 0
        self.payload = b"\x00" * 6
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Initialize an instance of the class ExtensionHeader.

        :param raw:
        :type raw:
        """
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < self.MIN_LEN:
            logging.warning("Data too short to parse extension hdr: "
                            "data len %u", dlen)
            return
        self.next_hdr, self._hdr_len = struct.unpack("!BB", raw[:2])
        assert dlen == len(self)
        self.set_payload(raw[2:])
        self.parsed = True

    def set_payload(self, payload):
        """
        Set payload, pad to 8 bytes if necessary, and update _hdr_len.
        """
        payload_len = len(payload)
        if payload_len < 6:  # FIXME(PSz): Should we (or ext developer) pad it?
            logging.warning("Extension is unpadded, adding padding.")
            payload += b"\x00" * abs(payload_len - 6)
            payload_len = 6
        payload_len -= 6  # That should be multiplication of 8.
        to_pad = payload_len % self.MIN_LEN
        if to_pad:  # FIXME(PSz): Should we (or ext developer) pad it?
            logging.warning("Extension is unpadded, adding padding.")
            payload += (self.MIN_LEN - to_pad) * b"\x00"
            payload_len += self.MIN_LEN - to_pad
        self._hdr_len = payload_len // self.MIN_LEN
        self.payload = payload

    def pack(self):
        """

        """
        return struct.pack("!BB", self.next_hdr, self._hdr_len) + self.payload

    def __len__(self):
        """
        Return length of extenion header in bytes.
        """
        return (self._hdr_len + 1) * self.MIN_LEN

    def __str__(self):
        """

        """
        return "[EH next hdr: %u, len: %u, payload: %s]" % (self.next_hdr,
                                                            len(self),
                                                            self.payload)


class TracerouteExt(ExtensionHeader):
    """
    0          8         16           32            48               64
    | next hdr | hdr len |               (padding)                   |
    |    ISD_0      |      AD_0       |    IFID_0   |   Timestamp_0  |
    |    ISD_1      |      AD_1       |    IFID_1   |   Timestamp_1  |
    ...

    Timestamps contain last 2 bytes of Unix time.

    """
    MIN_LEN = 8
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
        for hops in self.hops:
            ret_str += "    ISD:%d AD:%d IFID:%d TS:%d\n" % hops
        ret_str += "[Traceroute Ext - end, next_hdr:%d]" % self.next_hdr
        return ret_str


#TODO(PSz): move it somewhere
import time
def traceroute_ext_handler(**kwargs):
    """
    Handler for Traceroute extension.
    """
    # Operate passed extension, router's interface and topology
    ext = kwargs['ext']
    topo = kwargs['topo']
    iface = kwargs['iface']
    ts = int(time.time() * 1000) % 2**16 # truncate milliseconds to 2 bytes
    ext.append_hop(topo.isd_id, topo.ad_id, iface.if_id, ts)
