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
:mod:`scion_udp` --- UDP/SCION packets
======================================
"""
# Stdlib
import struct

# External
import scapy.utils

# SCION
from lib.defines import L4_UDP
from lib.errors import SCIONParseError
from lib.packet.packet_base import PacketBase
from lib.util import Raw


class SCIONUDPPacket(PacketBase):
    """
    Encapsulates the UDP header and payload for UDP/SCION packets.
    """
    HDR_LEN = 8
    MIN_LEN = HDR_LEN

    def __init__(self, raw=None):
        """

        :param tuple raw:
            Tuple of (`SCIONAddr`, `SCIONAddr`, bytes) for the source address,
            destination address, and raw UDP packet respectively.
        """
        super().__init__()
        self._src_addr = None
        self.src_port = None
        self._dst_addr = None
        self.dst_port = None

        if raw:
            self.parse(*raw)

    @classmethod
    def from_values(cls, src_addr, src_port, dst_addr, dst_port, payload=None):
        """
        Returns a SCIONUDPPacket with the values specified.
        """
        inst = cls()
        inst._src_addr = src_addr
        inst.src_port = src_port
        inst._dst_addr = dst_addr
        inst.dst_port = dst_port
        if payload is not None:
            inst.set_payload(payload)
        return inst

    def parse(self, src_addr, dst_addr, raw):
        data = Raw(raw, "SCIONUDPPacket", self.MIN_LEN, min_=True)
        self._src_addr = src_addr
        self._dst_addr = dst_addr
        self.src_port, self.dst_port, payload_len, checksum = \
            struct.unpack("!HHHH", data.pop(self.HDR_LEN))
        # Strip off udp header size.
        payload_len -= self.HDR_LEN
        if payload_len != len(data):
            raise SCIONParseError(
                "SCIONUDPPacket: payload length in header (%d) does not match "
                "supplied payload (%d)" % (payload_len, len(data)))
        self.set_payload(data.pop(payload_len), expected=checksum)

    def pack(self):
        checksum = self._calc_checksum()
        hdr = struct.pack("!HHHH", self.src_port, self.dst_port, len(self),
                          checksum)
        return hdr + self._payload

    def set_payload(self, payload, expected=None):
        super().set_payload(payload)
        if expected is None:
            return
        checksum = self._calc_checksum()
        if checksum != expected:
            raise SCIONParseError(
                "SCIONUDPPacket: checksum in header (%s) does not match "
                "checksum of payload (%s)" % (expected, checksum))

    def _calc_checksum(self):
        """
        Using a Pseudoheader of:
            - Source address
            - Destination address
            - L4 protocol type (UDP)
            - Source port
            - Destination port
            - Payload length
        """
        pseudo_header = b"".join([
            self._src_addr.pack(),
            self._dst_addr.pack(),
            struct.pack("!BHHH", L4_UDP, self.src_port, self.dst_port,
                        len(self)),
            self._payload,
        ])
        return scapy.utils.checksum(pseudo_header)

    def __len__(self):
        return self.HDR_LEN + len(self._payload)

    def __str__(self):
        return "[UDP sport: %s dport: %s len: %s]" % (
            self.src_port, self.dst_port, len(self))
