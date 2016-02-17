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
from lib.packet.packet_base import L4HeaderBase
from lib.packet.scion_addr import SCIONAddr
from lib.util import Raw, hex_str


class SCIONUDPHeader(L4HeaderBase):
    """
    Encapsulates the UDP header for UDP/SCION packets.
    """
    LEN = 8
    TYPE = L4_UDP
    NAME = "UDP"
    CHKSUM_LEN = 2

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param tuple raw:
            Tuple of (`SCIONAddr`, `SCIONAddr`, bytes, bytes) for the source
            address, destination address, raw UDP header and raw payload,
            respectively.
        """
        super().__init__()
        self._src = None
        self.src_port = None
        self._dst = None
        self.dst_port = None
        self._length = self.LEN
        self._checksum = b""

        if raw:
            src, dst, raw_hdr, payload = raw
            self._parse(src, dst, raw_hdr, payload)

    def _parse(self, src, dst, raw, payload):
        data = Raw(raw, "SCIONUDPHeader", self.LEN)
        self._src = src
        self._dst = dst
        self.src_port, self.dst_port, self._length = struct.unpack(
            "!HHH", data.pop(self.LEN - self.CHKSUM_LEN))
        self._checksum = data.pop(self.CHKSUM_LEN)
        # Strip off udp header size.
        payload_len = self._length - self.LEN
        if payload_len != len(payload):
            raise SCIONParseError(
                "SCIONUDPHeader: length in header (%dB) does not match "
                "supplied payload (%dB)" %
                (self._length, self.LEN + len(payload)))
        checksum = self._calc_checksum(payload)
        if checksum != self._checksum:
            raise SCIONParseError(
                "SCIONUDPHeader: checksum in header (%s) does not match "
                "checksum of supplied data (%s)" % (
                    hex_str(self._checksum), hex_str(checksum)))

    @classmethod
    def from_values(cls, src, src_port, dst, dst_port, payload=None):
        """
        Returns a SCIONUDPHeader with the values specified.
        """
        inst = cls()
        inst.update(src, src_port, dst, dst_port, payload)
        return inst

    def update(self, src=None, src_port=None, dst=None, dst_port=None,
               payload=None):
        if src is not None:
            self._src = src
        if src_port is not None:
            self.src_port = src_port
        if dst is not None:
            self._dst = dst
        if dst_port is not None:
            self.dst_port = dst_port
        if payload is not None:
            self._length = self.LEN + payload.total_len()
            self._checksum = self._calc_checksum(payload)

    def pack(self):
        raw = []
        raw.append(struct.pack("!HHH", self.src_port, self.dst_port,
                               self._length))
        raw.append(self._checksum)
        return b"".join(raw)

    def _calc_checksum(self, payload):
        """
        Using a Pseudoheader of:
            - Source address
            - Destination address
            - L4 protocol type (UDP)
            - Source port
            - Destination port
            - Payload length
        """
        assert isinstance(self._src, SCIONAddr)
        assert isinstance(self._dst, SCIONAddr)
        pseudo_header = b"".join([
            self._src.pack(), self._dst.pack(),
            struct.pack("!BHHH", L4_UDP, self.src_port, self.dst_port,
                        self._length),
            payload.pack_full(),
        ])
        chk_int = scapy.utils.checksum(pseudo_header)
        return struct.pack("!H", chk_int)

    def reverse(self):
        self._src, self._dst = self._dst, self._src
        self.src_port, self.dst_port = self.dst_port, self.src_port

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        return "UDP hdr (%sB): sport: %s dport: %s length: %sB checksum: %s" \
            % (self.LEN, self.src_port, self.dst_port,
               self._length, hex_str(self._checksum))
