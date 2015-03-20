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

from lib.defines import ISD_LEN, AD_LEN
from bitstring import BitArray
import bitstring
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
        # in case that len(addr) == 4, addr is binary string 
        if isinstance(addr, str) and len(addr) != 4: 
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

class AddressLengths(object):
    """
    Defines constants for the types of host addresses in SCION.
    """
    ADDR_NA = 0
    HOST_ADDR_SCION = 8
    HOST_ADDR_IPV4 = 4
    HOST_ADDR_IPV6 = 16
    HOST_ADDR_AIP = 20

class SCIONAddr(object):
    """
    Class for complete SCION addresses.
    addr ist HostAddr instance
    """
    def __init__(self, raw=None):
        self.isd = None 
        self.ad = None
        self.host_addr = None
        self.addr_len = 0 
        if raw:
            self.parse(raw)

    @classmethod
    def from_values(cls, isd, ad, host_addr):
        addr = SCIONAddr()
        addr.isd = isd
        addr.ad = ad
        addr.host_addr = host_addr
        addr.addr_len = ISD_LEN + AD_LEN + addr.addr_len
        return addr

    def parse(self, raw):
        assert isinstance(raw, bytes)
        addr_len = len(raw)
        if addr_len < ISD_LEN + AD_LEN:
            logging.warning("SCIONAddr: Data too short for parsing, len: %u",
                             addr_len)
            return
        bits = BitArray(bytes=raw[:ISD_LEN + AD_LEN])
        (self.isd, self.ad) = bits.unpack("uintbe:%u, uintbe:%u" % (ISD_LEN * 8,
                                                                    AD_LEN * 8))
        host_addr_len =  addr_len - ISD_LEN - AD_LEN
        if host_addr_len == AddressLengths.HOST_ADDR_IPV4:
            self.host_addr = IPv4HostAddr()
        elif host_addr_len == AddressLengths.HOST_ADDR_IPV6:
            self.host_addr = IPv6HostAddr()
        else:
            logging.warning("SCIONAddr: HostAddr unsupported, len: %u",
                            host_addr_len)
            return
        bits = BitArray(bytes=raw[ISD_LEN + AD_LEN:])
        (host_addr_int,) = bits.unpack("uintle:%u" % (host_addr_len * 8))
        self.host_addr.set_addr(host_addr_int)
        self.addr_len = ISD_LEN + AD_LEN + self.host_addr.addr_len

    def pack(self):
        pack_str = "uintbe:%u, uintbe:%u" % (ISD_LEN * 8, AD_LEN * 8)
        return (bitstring.pack(pack_str, self.isd, self.ad).bytes + 
                self.host_addr.addr)

    def __str__(self):
        return "(%u, %u, %s)" % (self.isd, self.ad, self.host_addr)
