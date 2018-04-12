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
:mod:`scion_addr` --- SCION host address specifications
=======================================================
"""
# Stdlib
import struct

# SCION
from lib.errors import SCIONIndexError, SCIONParseError
from lib.packet.packet_base import Serializable
from lib.packet.host_addr import (
    HostAddrBase,
    haddr_get_type,
)
from lib.util import Raw


class ISD_AS(Serializable):
    """
    Class for representing ISD-AS pair. The underlying type is a 64-bit unsigned int; ISD is
    represented by the top 16 bits (though the top 4 bits are currently reserved), and AS by the
    lower 48 bits.
    See formatting and allocations here:
    https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering
    """
    NAME = "ISD_AS"
    LEN = 8
    ISD_BITS = 16
    MAX_ISD = (1 << ISD_BITS) - 1
    AS_BITS = 48
    MAX_AS = (1 << AS_BITS) - 1
    BGP_AS_BITS = 32
    MAX_BGP_AS = (1 << BGP_AS_BITS) - 1
    HEX_AS_PARTS = 3  # E.g. ff00:0:abcd
    HEX_SEPARATOR = ":"
    HEX_FILE_SEPARATOR = "_"
    MAX_HEX_AS_PART = 0xffff

    def __init__(self, raw=None):
        self._isd = 0
        self._as = 0
        super().__init__(raw)

    def _parse(self, raw):  # pragma: no cover
        if isinstance(raw, bytes):
            self._parse_bytes(raw)
        elif isinstance(raw, int):
            self._parse_int(raw)
        else:
            self._parse_str(raw)

    def _parse_bytes(self, raw):
        """
        :param bytes raw: a byte string containing a 64-bit unsigned integer.
        """
        data = Raw(raw, self.NAME, self.LEN)
        isd_as = struct.unpack("!Q", data.pop())[0]
        self._parse_int(isd_as)

    def _parse_str(self, raw):
        """
        :param str raw: a string of the format "isd-as".
        """
        parts = raw.split("-")
        if len(parts) != 2:
            raise SCIONParseError("Unable to split ISD-AS in string: %s" % raw)
        isd_s, as_s = parts
        self._parse_isd_str(isd_s)
        for as_sep in [self.HEX_SEPARATOR, self.HEX_FILE_SEPARATOR]:
            if as_sep in as_s:
                self._parse_hex_as(as_s, as_sep)
                break
        else:
            self._parse_dec_as(as_s)

    def _parse_isd_str(self, raw):
        try:
            self._isd = int(raw)
        except ValueError:
            raise SCIONParseError("Unable to parse ISD from string: %s" % raw) from None
        if self._isd > self.MAX_ISD:
            raise SCIONParseError("ISD too large (max: %d): %s" % (self.MAX_ISD, raw))

    def _parse_dec_as(self, raw):
        try:
            self._as = int(raw, base=10)
        except ValueError:
            raise SCIONParseError("Unable to parse decimal AS from string: %s" % raw) from None
        if self._as > self.MAX_BGP_AS:
            raise SCIONParseError("Decimal AS too large (max: %d): %s" % (self.MAX_BGP_AS, raw))

    def _parse_hex_as(self, raw, as_sep=HEX_SEPARATOR):
        try:
            as_parts = raw.split(as_sep)
        except ValueError:
            raise SCIONParseError("Unable to parse hex AS from string: %s" % raw) from None
        if len(as_parts) != self.HEX_AS_PARTS:
            raise SCIONParseError(
                "Wrong number of separators (%s) in hex AS number (expected: %d actual: %s): %s" %
                (self.HEX_SEPARATOR, self.HEX_AS_PARTS,  as_parts, raw))
        self._as = 0
        for i, s in enumerate(as_parts):
            self._as <<= 16
            v = int(s, base=16)
            if v > self.MAX_HEX_AS_PART:
                raise SCIONParseError("Hex AS number has part greater than %x: %s" %
                                      (self.MAX_HEX_AS_PART, raw))
            self._as |= v
        if self._as > self.MAX_AS:
            raise SCIONParseError("AS too large (max: %d): %s" % (self.MAX_AS, raw))

    def _parse_int(self, raw):
        """
        :param int raw: a 64-bit unsigned integer
        """
        self._isd = raw >> self.AS_BITS
        self._as = raw & self.MAX_AS

    @classmethod
    def from_values(cls, isd, as_):  # pragma: no cover
        inst = cls()
        inst._isd = isd
        inst._as = as_
        return inst

    def pack(self):
        return struct.pack("!Q", self.int())

    def int(self):
        isd_as = self._isd << self.AS_BITS
        isd_as |= self._as & self.MAX_AS
        return isd_as

    def any_as(self):  # pragma: no cover
        return self.from_values(self._isd, 0)

    def is_zero(self):  # pragma: no cover
        return self._isd == 0 and self._as == 0

    def params(self, name="first"):  # pragma: no cover
        """Provides parameters for querying PathSegmentDB"""
        if self._as == 0:
            return {"%s_isd" % name: self._isd}
        else:
            return {"%s_ia" % name: self}

    def __eq__(self, other):  # pragma: no cover
        return self._isd == other._isd and self._as == other._as

    def __getitem__(self, idx):  # pragma: no cover
        if idx == 0:
            return self._isd
        elif idx == 1:
            return self._as
        else:
            raise SCIONIndexError("Invalid index used on %s object: %s" % (
                                  (self.NAME, idx)))

    def __int__(self):  # pragma: no cover
        return self.int()

    def __iter__(self):  # pragma: no cover
        yield self._isd
        yield self._as

    def isd_str(self):
        s = str(self._isd)
        if self._isd > self.MAX_ISD:
            return "%s [Illegal ISD: larger than %d]" % (s, self.MAX_ISD)
        return s

    def as_str(self, sep=HEX_SEPARATOR):
        dec_str = str(self._as)
        if self._as > self.MAX_AS:
            return "%s [Illegal AS: larger than %d]" % (dec_str, self.MAX_AS)
        if self._as <= self.MAX_BGP_AS:
            return str(self._as)
        s = []
        as_ = self._as
        for i in range(self.HEX_AS_PARTS):
            s.insert(0, "%x" % (as_ & self.MAX_HEX_AS_PART))
            as_ >>= 16
        return sep.join(s)

    def as_file_fmt(self):
        return self.as_str(self.HEX_FILE_SEPARATOR)

    def file_fmt(self):
        return "%s-%s" % (self.isd_str(), self.as_file_fmt())

    def __str__(self, as_sep=HEX_SEPARATOR):
        return "%s-%s" % (self.isd_str(), self.as_str(as_sep))

    def __repr__(self):  # pragma: no cover
        return "ISD_AS(isd=%s, as=%s)" % (self._isd, self._as)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __hash__(self):  # pragma: no cover
        return hash(str(self))


class SCIONAddr(object):
    """
    Class for complete SCION addresses.

    :ivar ISD_AS isd_as: ISD-AS identifier.
    :ivar HostAddrBase host: host address.
    :ivar int addr_len: address length.
    """
    def __init__(self, addr_info=()):  # pragma: no cover
        """
        Initialize an instance of the class SCIONAddr.

        :param addr_info: Tuple of (addr_type, addr) for the host address
        """
        self.isd_as = None
        self.host = None
        if addr_info:
            self._parse(*addr_info)

    def _parse(self, addr_type, raw):
        """
        Parse a raw byte string.

        :param int addr_type: Host address type
        :param bytes raw: raw bytes.
        """
        haddr_type = haddr_get_type(addr_type)
        addr_len = ISD_AS.LEN + haddr_type.LEN
        data = Raw(raw, "SCIONAddr", addr_len, min_=True)
        self.isd_as = ISD_AS(data.pop(ISD_AS.LEN))
        self.host = haddr_type(data.pop(haddr_type.LEN))

    @classmethod
    def from_values(cls, isd_as, host):  # pragma: no cover
        """
        Create an instance of the class SCIONAddr.

        :param ISD_AS isd_as: ISD-AS identifier.
        :param HostAddrBase host: host address
        """
        assert isinstance(host, HostAddrBase), type(host)
        addr = cls()
        addr.isd_as = isd_as
        addr.host = host
        return addr

    def pack(self):  # pragma: no cover
        """
        Pack the class variables into a byte string.

        :returns: a byte string containing ISD ID, AS ID, and host address.
        :rtype: bytes
        """
        return self.isd_as.pack() + self.host.pack()

    @classmethod
    def calc_len(cls, type_):  # pragma: no cover
        class_ = haddr_get_type(type_)
        return ISD_AS.LEN + class_.LEN

    def __len__(self):  # pragma: no cover
        return len(self.isd_as) + len(self.host)

    def __eq__(self, other):  # pragma: no cover
        return (self.isd_as == other.isd_as and
                self.host == other.host)

    def __str__(self):
        """
        Return a string containing ISD-AS, and host address.
        """
        return "(%s (%s) %s)" % (self.isd_as, self.host.name(), self.host)
