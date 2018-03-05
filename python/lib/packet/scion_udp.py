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
from pypacker import checksum

# SCION
from lib.errors import SCIONChecksumFailed
from lib.packet.packet_base import L4HeaderBase
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scmp.errors import SCMPBadPktLen
from lib.util import Raw, hex_str
from lib.types import L4Proto


class SCIONUDPHeader(L4HeaderBase):
    """
    Encapsulates the UDP header for UDP/SCION packets.
    """
    LEN = 8
    TYPE = L4Proto.UDP
    NAME = "SCIONUDPHeader"
    CHKSUM_LEN = 2

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param tuple raw:
            Tuple of (`SCIONAddr`, `SCIONAddr`, bytes) for the source
            address, destination address, and raw UDP header respectively.
        """
        super().__init__()
        self._src = None
        self.src_port = None
        self._dst = None
        self.dst_port = None
        self.total_len = self.LEN
        self._checksum = b""

        if raw:
            src, dst, raw_hdr = raw
            self._parse(src, dst, raw_hdr)

    def _parse(self, src, dst, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self._src = src
        self._dst = dst
        self.src_port, self.dst_port, self.total_len, self._checksum = \
            struct.unpack("!HHH2s", data.pop(self.LEN))

    @classmethod
    def from_values(cls, src, src_port, dst, dst_port):  # pragma: no cover
        """Returns an SCIONUDPHeader with the values specified."""
        inst = cls()
        inst.update(src, src_port, dst, dst_port)
        return inst

    def update(self, src=None, src_port=None, dst=None,
               dst_port=None):  # pragma: no cover
        if src is not None:
            self._src = src
        if src_port is not None:
            self.src_port = src_port
        if dst is not None:
            self._dst = dst
        if dst_port is not None:
            self.dst_port = dst_port

    def _pack(self, checksum):  # pragma: no cover
        return struct.pack("!HHH2s", self.src_port, self.dst_port,
                           self.total_len, checksum)

    def validate(self, payload):
        # Strip off udp header size.
        payload_len = self.total_len - self.LEN
        if payload_len != len(payload):
            raise SCMPBadPktLen(
                "%s: length in header (%dB) does not match "
                "supplied payload (%dB)" %
                (self.NAME, self.total_len, self.LEN + len(payload)), 0)
        checksum = self._calc_checksum(payload)
        if checksum != self._checksum:
            raise SCIONChecksumFailed(
                "%s: checksum in header (%s) does not match "
                "checksum of supplied data (%s)" % (
                    self.NAME, hex_str(self._checksum), hex_str(checksum)))

    def _calc_checksum(self, payload):
        """
        Using a Pseudoheader of:
            - Source address
            - Destination address
            - L4 protocol type (UDP)
            - UDP header, excluding checksum
        """
        assert isinstance(self._src, SCIONAddr), type(self._src)
        assert isinstance(self._dst, SCIONAddr), type(self._dst)
        pseudo_header = b"".join([
            self._dst.isd_as.pack(), self._src.isd_as.pack(),
            self._dst.host.pack(), self._src.host.pack(),
            b"\x00", struct.pack("!B", L4Proto.UDP),
            self.pack(payload, checksum=bytes(2)), payload,
        ])
        chk_int = checksum.in_cksum(pseudo_header)
        return struct.pack("!H", chk_int)

    def reverse(self):
        self._src, self._dst = self._dst, self._src
        self.src_port, self.dst_port = self.dst_port, self.src_port

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        return "UDP hdr (%sB): sport: %s dport: %s length: %sB checksum: %s" \
            % (self.LEN, self.src_port, self.dst_port,
               self.total_len, hex_str(self._checksum))
