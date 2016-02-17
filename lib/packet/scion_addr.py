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
from lib.packet.host_addr import (
    HostAddrBase,
    haddr_get_type,
)
from lib.util import Raw


class ISD_AS(object):
    """
    Class for representing isd-as pair.
    """
    NAME = "ISD_AS"
    LEN = 4

    def __init__(self, raw=None):
        self._isd = None
        self._as = None
        if raw:
            self._parse(raw)

    def _parse(self, raw):  # pragma: no cover
        if isinstance(raw, bytes):
            self._parse_bytes(raw)
        else:
            self._parse_str(raw)

    def _parse_bytes(self, raw):
        """
        :param bytes raw:
            a byte string containing ISD ID, AS ID. ISD and AS are respectively
            represented as 12 and 20 most significant bits.
        """
        data = Raw(raw, self.NAME, self.LEN)
        isd_as = struct.unpack("!I", data.pop())[0]
        self._isd = isd_as >> 20
        self._as = isd_as & 0x000fffff

    def _parse_str(self, raw):
        """
        :param str raw: a string of the format "isd-as".
        """
        isd, as_ = raw.split("-", 1)
        try:
            self._isd = int(isd)
        except ValueError:
            raise SCIONParseError("Unable to parse ISD from string: %s", raw)
        try:
            self._as = int(as_)
        except ValueError:
            raise SCIONParseError("Unable to parse AS from string: %s", raw)

    @classmethod
    def from_values(cls, isd, as_):  # pragma: no cover
        inst = cls()
        inst._isd = isd
        inst._as = as_
        return inst

    def pack(self):
        return struct.pack("!I", self.int())

    def int(self):
        isd_as = self._isd << 20
        isd_as |= self._as & 0x000fffff
        return isd_as

    def any_as(self):
        return self.from_values(self._isd, 0)

    def params(self, name="first"):
        """Provides parameters for querying PathSegmentDB"""
        if self._as == 0:
            return {"%s_isd" % name: self._isd}
        else:
            return {"%s_ia" % name: self}

    def __eq__(self, other):
        return self._isd == other._isd and self._as == other._as

    def __getitem__(self, idx):  # pragma: no cover
        if idx == 0:
            return self._isd
        elif idx == 1:
            return self._as
        else:
            raise SCIONIndexError("Invalid index used on %s object: %s" % (
                                  (self.NAME, idx)))

    def __iter__(self):
        yield self._isd
        yield self._as

    def __str__(self):
        return "%s-%s" % (self._isd, self._as)

    def __repr__(self):
        return "ISD_AS(isd=%s, as=%s)" % (self._isd, self._as)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __hash__(self):
        return hash(str(self))


class SCIONAddr(object):
    """
    Class for complete SCION addresses.

    :ivar int isd_as: ISD-AS identifier.
    :ivar HostAddrBase host: host address.
    :ivar int addr_len: address length.
    """
    def __init__(self, addr_info=()):
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
        assert isinstance(host, HostAddrBase)
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
    def calc_len(cls, type_):
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
