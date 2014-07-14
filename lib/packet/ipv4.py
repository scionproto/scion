"""
ipv4.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

#======================================================================
#
#                          IPv4 Header Format
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |Version|  IHL  |Type of Service|          Total Length         |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |         Identification        |Flags|      Fragment Offset    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Time to Live |    Protocol   |         Header Checksum       |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Source Address                          |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Destination Address                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Options                    |    Padding    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================

import array
import logging
from socket import ntohs
import struct
import time

from lib.packet.host_addr import IPv4HostAddr
from lib.packet.packet_base import PacketBase, HeaderBase


def checksum(data, start=0, skip=None):
    """
    Calculate standard internet checksum over data starting at start'th byte

    @param skip: If specified, it's the word offset of a word in data to
                 "skip" (as if it were zero). The purpose is when data is recv
                 data which contains a computed checksum that you are trying to
                 verify -- you want to skip that word since it was zero when
                 the checksum was initially calculated.
    """
    if len(data) % 2 != 0:
        arr = array.array('H', data[:-1])
    else:
        arr = array.array('H', data)

    if skip is not None:
        for i in range(0, len(arr)):
            if i == skip:
                continue
            start += arr[i]
    else:
        for i in range(0, len(arr)):
            start += arr[i]

    if len(data) % 2 != 0:
        start += struct.unpack('H', data[-1] + '\0')[0]

    start = (start >> 16) + (start & 0xffff)
    start += (start >> 16)

    return ntohs(~start & 0xffff)


class IPv4Header(HeaderBase):
    """
    IPv4 packet header class
    """

    MIN_LEN = 20

    ip_id = int(time.time())

    def __init__(self, raw=None):
        HeaderBase.__init__(self)
        self.v = 4
        self.hdr_len = IPv4Packet.MIN_LEN // 4
        self.tos = 0
        self.total_len = IPv4Packet.MIN_LEN
        IPv4Header.ip_id = (IPv4Header.ip_id + 1) & 0xffff
        self.id = IPv4Header.ip_id
        self.flags = 0
        self.frag = 0
        self.ttl = 64
        self.protocol = 0
        self.check_sum = 0
        self.srcip = IPv4HostAddr("0.0.0.0")
        self.dstip = IPv4HostAddr("0.0.0.0")

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < IPv4Header.MIN_LEN:
            logging.warning("Data too short to parse IPv4 packet: "
                            "data len %u", dlen)
            return
        (vhl, self.tos, self.total_len, self.id, self.frag, self.ttl,
         self.protocol, self.check_sum, srcip, dstip) = \
            struct.unpack('!BBHHHBBHII', raw[:IPv4Packet.MIN_LEN])

        self.v = vhl >> 4
        self.hdr_len = vhl & 0x0f

        self.flags = self.frag >> 13
        self.frag = self.frag & 0x1fff

        self.dstip = IPv4HostAddr(dstip)
        self.srcip = IPv4HostAddr(srcip)

        self.parsed = True

    def pack(self):
        """
        Packs the header and returns a byte array.
        """
        return struct.pack('!BBHHHBBHII', (self.v << 4) + self.hdr_len,
                           self.tos, self.total_len, self.id,
                           (self.flags << 13) | self.frag, self.ttl,
                           self.protocol, self.check_sum, self.srcip.to_int(),
                           self.dstip.to_int())

    def __len__(self):
        return self.hdr_len * 4

    def __str__(self):
        s = "[IP %s>%s (proto: %d cs:%02x v:%s hl:%s tl:%s ttl:%s)]" % (
            self.srcip, self.dstip, self.protocol, self.check_sum,
            self.v, self.hdr_len, self.total_len, self.ttl)

        return s


class IPv4Packet(PacketBase):
    """
    IPv4 packet class.
    """

    MIN_LEN = 20

    def __init__(self, raw=None):
        PacketBase.__init__(self)

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        assert isinstance(raw, bytes)
        dlen = len(raw)
        self.raw = raw
        if dlen < IPv4Packet.MIN_LEN:
            logging.warning("Data too short to parse IPv4 packet: "
                            "data len %u", dlen)
            return
        self.hdr = IPv4Header(raw)

        self.payload = raw[self.hdr.hdr_len * 4:]
        self.parsed = True

    def pack(self):
        """
        Packs the header and the payload and returns a byte array.
        """
        # Adjust total len and checksum in header.
        self.hdr.total_len = len(self.hdr) + len(self.payload)
        self.hdr.check_sum = 0
        self.hdr.check_sum = checksum(self.hdr.pack())
        data = []
        data.append(self.hdr.pack())
        if isinstance(self.payload, PacketBase):
            data.append(self.payload.pack())
        else:
            data.append(self.payload)

        return b"".join(data)
