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
from abc import ABCMeta, abstractmethod
from ipaddress import (
    AddressValueError,
    IPV4LENGTH,
    IPV6LENGTH,
    IPv4Address,
    IPv6Address,
)

# SCION
from lib.errors import SCIONBaseError, SCIONParseError
from lib.defines import (
    ADDR_NONE_TYPE,
    ADDR_IPV4_TYPE,
    ADDR_IPV6_TYPE,
    ADDR_SVC_TYPE,
)
from lib.util import Raw

ADDR_NONE_BYTES = 0
ADDR_IPV4_BYTES = IPV4LENGTH // 8
ADDR_IPV6_BYTES = IPV6LENGTH // 8
ADDR_SVC_BYTES = 2

ADDR_NONE_NAME = "NONE"
ADDR_IPV4_NAME = "IPv4"
ADDR_IPV6_NAME = "IPv6"
ADDR_SVC_NAME = "SVC"


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


class HostAddrBase(object, metaclass=ABCMeta):
    """
    Base HostAddr class. Should not be used directly.
    """
    TYPE = None
    LEN = None
    NAME = None

    def __init__(self, addr, raw=True):
        """
        :param addr: Address to parse/store.
        :param bool raw: Does the address need to be parsed?
        """
        self.addr = None
        if raw:
            self._parse(addr)
        else:
            self.addr = addr

    @abstractmethod
    def _parse(self, raw):
        raise NotImplementedError

    @abstractmethod
    def pack(self):
        """
        :return: a packed representation of the host address
        :rtype: bytes
        """
        raise NotImplementedError

    def __str__(self):
        return str(self.addr)

    def __len__(self):
        return self.LEN

    def __eq__(self, other):
        return (self.TYPE == other.TYPE) and (self.addr == other.addr)


class HostAddrNone(object):
    """
    Host "None" address. Used to indicate there's no address.
    """
    TYPE = ADDR_NONE_TYPE
    LEN = ADDR_NONE_BYTES
    NAME = ADDR_NONE_NAME

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
    TYPE = ADDR_IPV4_TYPE
    LEN = ADDR_IPV4_BYTES
    NAME = ADDR_IPV4_NAME

    def _parse(self, raw):
        """
        Parse IPv4 address

        :param raw: Can be either `bytes` or `str`
        """
        try:
            self.addr = IPv4Address(raw)
        except AddressValueError as e:
            raise SCIONParseError("Unable to parse %s address: %s" % (self.NAME, e)) \
                from None

    def pack(self):
        return self.addr.packed


class HostAddrIPv6(HostAddrBase):
    """
    Host IPv6 address.
    """
    TYPE = ADDR_IPV6_TYPE
    LEN = ADDR_IPV6_BYTES
    NAME = ADDR_IPV6_NAME

    def _parse(self, raw):
        """
        Parse IPv6 address

        :param raw: Can be either `bytes` or `str`
        """
        try:
            self.addr = IPv6Address(raw)
        except AddressValueError as e:
            raise SCIONParseError("Unable to parse %s address: %s" % (self.NAME, e)) \
                from None

    def pack(self):
        return self.addr.packed


class HostAddrSVC(HostAddrBase):
    """
    Host "SVC" address. This is a pseudo- address type used for SCION services.
    """
    TYPE = ADDR_SVC_TYPE
    LEN = ADDR_SVC_BYTES
    NAME = ADDR_SVC_NAME

    def _parse(self, raw):
        """
        Parse SVC address

        :param bytes raw: Raw SVC address
        """
        data = Raw(raw, "HostAddrSVC", self.LEN)
        self.addr = struct.unpack("!H", data.pop(self.LEN))[0]

    def pack(self):
        return struct.pack("!H", self.addr)


_map = {
    # By type
    ADDR_NONE_TYPE: HostAddrNone,
    ADDR_IPV4_TYPE: HostAddrIPv4,
    ADDR_IPV6_TYPE: HostAddrIPv6,
    ADDR_SVC_TYPE: HostAddrSVC,
    # By name
    ADDR_NONE_NAME: HostAddrNone,
    ADDR_IPV4_NAME: HostAddrIPv4,
    ADDR_IPV6_NAME: HostAddrIPv6,
    ADDR_SVC_NAME: HostAddrSVC,
}


def haddr_get_type(type_):
    """
    Look up host address class by type.

    :param type\_: host address type. E.g. ``1`` or ``"IPv4"``.
    :type type\_: int or string
    """
    try:
        return _map[type_]
    except KeyError:
        raise HostAddrInvalidType("Unknown host addr type '%s'" % type_) \
            from None


def haddr_parse(type_, *args, **kwargs):
    """
    Parse host address and return object.

    :param type\_: host address type. E.g. ``1`` or ``"IPv4"``.
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
