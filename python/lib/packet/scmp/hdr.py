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
:mod:`hdr` --- SCMP Header
======================================
"""
# Stdlib
import struct
import time

# External
from pypacker import checksum

# SCION
from lib.errors import SCIONChecksumFailed
from lib.packet.packet_base import L4HeaderBase
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scmp.errors import SCMPBadPktLen
from lib.packet.scmp.types import SCMPClass
from lib.packet.scmp.util import scmp_type_name
from lib.types import L4Proto
from lib.util import Raw, hex_str, iso_timestamp


class SCMPHeader(L4HeaderBase):
    """
    Encapsulates the SCMP Header for SCMP packets.
    """
    NAME = "SCMPHeader"
    # Class(2B), Type(2B), Len(2B), Checksum(2B), Timestamp(8B)
    STRUCT_FMT = "!HHH2sQ"
    LEN = struct.calcsize(STRUCT_FMT)
    TYPE = L4Proto.SCMP

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param tuple raw:
            Tuple of (`SCIONAddr`, `SCIONAddr`, bytes) for the source
            address, destination address, and raw SCMP header respectively.
        """
        super().__init__()
        # Header fields
        self.class_ = None
        self.type = None
        self.total_len = self.LEN
        self._checksum = b""
        self.timestamp = 0
        # Meta-data
        self._src = None
        self._dst = None
        if raw:
            src, dst, raw_hdr = raw
            self._parse(src, dst, raw_hdr)

    def _parse(self, src, dst, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self._src = src
        self._dst = dst
        (self.class_, self.type, self.total_len, self._checksum,
         self.timestamp) = struct.unpack(self.STRUCT_FMT, data.pop())

    @classmethod
    def from_values(cls, src, dst, class_, type_):
        """
        Returns an SCMPHeader with the values specified.
        """
        inst = cls()
        inst.timestamp = int(time.time() * 1000000)
        inst.update(src, dst, class_, type_)
        return inst

    def update(self, src=None, dst=None, class_=None,
               type_=None):  # pragma: no cover
        if src is not None:
            self._src = src
        if dst is not None:
            self._dst = dst
        if class_ is not None:
            self.class_ = class_
        if type_ is not None:
            self.type = type_

    def _pack(self, checksum):  # pragma: no cover
        return struct.pack(self.STRUCT_FMT, self.class_, self.type,
                           self.total_len, checksum, self.timestamp)

    def reverse(self):  # pragma: no cover
        pass

    def validate(self, payload):
        # Strip off header size.
        payload_len = self.total_len - self.LEN
        if payload_len != len(payload):
            raise SCMPBadPktLen(
                "%s: length in header (%dB) does not match "
                "supplied payload (%dB)" %
                (self.NAME, self.total_len, self.LEN + len(payload)))
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
            - L4 protocol type (SCMP)
            - SCMP header, excluding checksum
        """
        assert isinstance(self._src, SCIONAddr), type(self._src)
        assert isinstance(self._dst, SCIONAddr), type(self._dst)
        pseudo_header = b"".join([
            self._dst.isd_as.pack(), self._src.isd_as.pack(),
            self._dst.host.pack(), self._src.host.pack(),
            b"\x00", struct.pack("!B", L4Proto.SCMP),
            self.pack(payload, checksum=bytes(2)), payload,
        ])
        chk_int = checksum.in_cksum(pseudo_header)
        return struct.pack("!H", chk_int)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        return ("%s(%sB): class: %s type: %s "
                "length: %sB checksum: %s timestamp: %s" % (
                    self.NAME, self.LEN, SCMPClass.to_str(self.class_),
                    scmp_type_name(self.class_, self.type),
                    self.total_len, hex_str(self._checksum),
                    iso_timestamp(self.timestamp / 1000000)))
