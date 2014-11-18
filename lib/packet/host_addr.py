#host_addr.py

#Copyright 2014 ETH Zurich

#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
"""
:mod:`host_addr` --- SCION host address specifications
======================================================

Module docstring here.

.. note::
    Fill in the docstring.
"""

import socket
import struct


class AddressLengths(object):
    """
    Defines constants for the types of host addresses in SCION.
    """
    ADDR_NA = 0
    HOST_ADDR_SCION = 8
    HOST_ADDR_IPV4 = 4
    HOST_ADDR_IPV6 = 16
    HOST_ADDR_AIP = 20


class HostAddr(object):
    """
    Base class for the different host address types.
    """
    def __init__(self):
        self.addr_len = 0
        self._addr = 0

    @property
    def addr(self):
        return self._addr

    @addr.setter
    def addr(self, addr):
        self.set_addr(addr)

    def set_addr(self, addr):
        self._addr = addr

    def to_int(self, endianness='big'):
        """
        Returns the address in integer format.

        :param endianness: the endiannness to use when converting. Must be
            'big' or 'little'.
        :type endianness: str
        :returns: an integer representation of the address stored in the :class:`HostAddr` object.
        :rtype: int
        """
        return int.from_bytes(self.addr, endianness)

    def __str__(self):
        return str(self.addr)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.addr == other.addr

    def __hash__(self):
        return hash(self.addr)


class IPv4HostAddr(HostAddr):
    """
    Class for IPv4 host addresses.
    """
    def __init__(self, addr=None):
        super(IPv4HostAddr, self).__init__()
        self.addr_len = AddressLengths.HOST_ADDR_IPV4
        if addr is not None:
            self.addr = addr

    def set_addr(self, addr):
        if isinstance(addr, str):
            self._addr = socket.inet_aton(addr)
        elif isinstance(addr, int):
            self._addr = struct.pack("I", addr)
        else:
            self._addr = addr

    def __str__(self):
        return socket.inet_ntoa(self._addr)


class IPv6HostAddr(HostAddr):
    """
    Class for IPv6 host addresses.
    """
    def __init__(self, addr=None):
        HostAddr.__init__(self)
        self.addr_len = AddressLengths.HOST_ADDR_IPV6
        if addr is not None:
            self.addr = addr

    def set_addr(self, addr):
        if isinstance(addr, str):
            self._addr = socket.inet_pton(socket.AF_INET6, addr)
        else:
            self._addr = addr

    def __str__(self):
        return socket.inet_ntop(socket.AF_INET6, self.addr)


class SCIONHostAddr(HostAddr):
    """
    Class for SCION host addresses.
    """
    def __init__(self, addr=None):
        HostAddr.__init__(self)
        self.addr_len = AddressLengths.HOST_ADDR_SCION
        if addr is not None:
            self.addr = addr
