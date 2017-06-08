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
:mod:`host_addr` --- L2 host address library
============================================
"""

# Stdlib
import struct

# External
from external.ipaddress import (
    AddressValueError,
    IPV4LENGTH,
    IPV6LENGTH,
    IPv4Interface,
    IPv6Interface,
)

# SCION
from lib.errors import SCIONBaseError, SCIONParseError
from lib.packet.packet_base import Serializable
from lib.types import AddrType
from lib.util import Raw


class HostAddrBaseError(SCIONBaseError):
    """
    Base exception for HostAddr errors.
    """
    pass


class HostAddrInvalidType(SCIONBaseError):
    """
    HostAddr type is invalid.
    """
    pass


class HostAddrBase(Serializable):
    """
    Base HostAddr class. Should not be used directly.
    """
    TYPE = None
    LEN = None

    def __init__(self, addr, raw=True):  # pragma: no cover
        """
        :param addr: Address to parse/store.
        :param bool raw: Does the address need to be parsed?
        """
        self.addr = None
        if raw:
            self._parse(addr)
        else:
            self.addr = addr

    def from_values(self, *args, **kwargs):
        raise NotImplementedError

    @classmethod
    def name(cls):
        return AddrType.to_str(cls.TYPE)

    def __str__(self):  # pragma: no cover
        return str(self.addr)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __eq__(self, other):  # pragma: no cover
        if other is None:
            return False
        return (self.TYPE == other.TYPE) and (self.addr == other.addr)

    def __lt__(self, other):  # pragma: no cover
        return str(self) < str(other)

    def __hash__(self):
        return hash(self.pack())


class HostAddrNone(HostAddrBase):  # pragma: no cover
    """
    Host "None" address. Used to indicate there's no address.
    """
    TYPE = AddrType.NONE
    LEN = 0

    def __init__(self):
        self.addr = None

    def _parse(self, raw):
        raise NotImplementedError

    def pack(self):
        return b""


class HostAddrIPv4(HostAddrBase):
    """
    Host IPv4 address.
    """
    TYPE = AddrType.IPV4
    LEN = IPV4LENGTH // 8

    def _parse(self, raw):
        """
        Parse IPv4 address

        :param raw: Can be either `bytes` or `str`
        """
        try:
            intf = IPv4Interface(raw)
        except AddressValueError as e:
            raise SCIONParseError("Unable to parse %s address: %s" %
                                  (self.name(), e)) from None
        self.addr = intf.ip

    def pack(self):  # pragma: no cover
        return self.addr.packed


class HostAddrIPv6(HostAddrBase):
    """
    Host IPv6 address.
    """
    TYPE = AddrType.IPV6
    LEN = IPV6LENGTH // 8

    def _parse(self, raw):
        """
        Parse IPv6 address

        :param raw: Can be either `bytes` or `str`
        """
        try:
            intf = IPv6Interface(raw)
        except AddressValueError as e:
            raise SCIONParseError("Unable to parse %s address: %s" %
                                  (self.name(), e)) from None
        self.addr = intf.ip

    def pack(self):  # pragma: no cover
        return self.addr.packed


class HostAddrSVC(HostAddrBase):
    """
    Host "SVC" address. This is a pseudo- address type used for SCION services.
    """
    TYPE = AddrType.SVC
    LEN = 2
    NAME = "HostAddrSVC"
    MCAST = 0x8000

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.addr = struct.unpack("!H", data.pop(self.LEN))[0]

    def pack(self):  # pragma: no cover
        return struct.pack("!H", self.addr)

    def is_mcast(self):  # pragma: no cover
        return self.addr & self.MCAST

    def multicast(self):
        return HostAddrSVC(self.addr | self.MCAST, raw=False)

    def anycast(self):
        return HostAddrSVC(self.addr & ~self.MCAST, raw=False)

    def __str__(self):
        s = "0x%02x" % (self.addr & ~self.MCAST)
        if self.is_mcast():
            return s + " M"
        return s + " A"


_map = {
    # By type
    AddrType.NONE: HostAddrNone,
    AddrType.IPV4: HostAddrIPv4,
    AddrType.IPV6: HostAddrIPv6,
    AddrType.SVC: HostAddrSVC,
    # By name
    "NONE": HostAddrNone,
    "IPV4": HostAddrIPv4,
    "IPV6": HostAddrIPv6,
    "SVC": HostAddrSVC,
}


def haddr_get_type(type_):  # pragma: no cover
    """
    Look up host address class by type.

    :param type\_: host address type. E.g. ``1`` or ``"IPV4"``.
    :type type\_: int or string
    """
    try:
        return _map[type_]
    except KeyError:
        raise HostAddrInvalidType("Unknown host addr type '%s'" %
                                  type_) from None


def haddr_parse(type_, *args, **kwargs):  # pragma: no cover
    """
    Parse host address and return object.

    :param type\_: host address type. E.g. ``1`` or ``"IPV4"``.
    :type type\_: int or string
    :param \*args:
        Arguments to pass to the host address object constructor. E.g.
        ``"127.0.0.1"``.
    :param \*\*kwargs:
        Keyword args to pass to the host address object constructor. E.g.
        ``raw=False``.
    """
    typecls = haddr_get_type(type_)
    return typecls(*args, **kwargs)


def haddr_parse_interface(intf):
    """
    Try to parse a string as either an ipv6 or ipv4 interface

    :param str interface: E.g. ``127.0.0.1/8``.
    """
    for type_ in AddrType.IPV6, AddrType.IPV4:
        try:
            return haddr_parse(type_, intf)
        except SCIONParseError:
            pass
    else:
        raise SCIONParseError("Unable to parse interface '%s'" % intf)
