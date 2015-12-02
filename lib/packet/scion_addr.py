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
from collections import namedtuple

# SCION
from lib.packet.host_addr import (
    HostAddrBase,
    haddr_get_type,
)
from lib.util import Raw


class ISD_AD(namedtuple('ISD_AD', 'isd ad')):
    """
    Class for representing isd,ad pair.

    :ivar int isd: ISD identifier.
    :ivar int ad: AD identifier.
    """
    NAME = "ISD_AD"
    LEN = 4

    @classmethod
    def from_raw(cls, raw):
        """
        Create an instance of the class ISD_AD.

        :param bytes raw:
            a byte string containing ISD ID, AD ID. ISD and AD are respectively
            represented as 12 and 20 most significant bits.
        :returns: ISD, AD tuple.
        :rtype: ISD_AD
        """
        data = Raw(raw, cls.NAME, cls.LEN)
        isd_ad = struct.unpack("!I", data.pop(cls.LEN))[0]
        isd = isd_ad >> 20
        ad = isd_ad & 0x000fffff
        return cls(isd, ad)

    def pack(self):
        """
        Pack the class variables into a byte string.

        :returns:
            a 4B byte string containing ISD ID (first 12 bits), AD ID
            (remaining 20 bits).
        :rtype: bytes
        """
        return struct.pack("!I", self.int())

    def int(self):
        """
        Return an integer representation of the isd/ad tuple.
        """
        isd = self.isd << 20
        ad = self.ad & 0x000fffff
        return isd + ad

    def __len__(self):  # pragma: no cover
        return self.LEN


class SCIONAddr(object):
    """
    Class for complete SCION addresses.

    :ivar int isd_id: ISD identifier.
    :ivar int ad_id: AD identifier.
    :ivar HostAddrBase host_addr: host address.
    :ivar int addr_len: address length.
    """
    def __init__(self, addr_info=()):
        """
        Initialize an instance of the class SCIONAddr.

        :param addr_info: Tuple of (addr_type, addr) for the host address
        """
        self.isd_id = None
        self.ad_id = None
        self.host_addr = None
        self.addr_len = 0
        if addr_info:
            self.parse(*addr_info)

    @classmethod
    def from_values(cls, isd_id, ad_id, host_addr):
        """
        Create an instance of the class SCIONAddr.

        :param int isd_id: ISD identifier.
        :param int ad_id: AD identifier.
        :param HostAddrBase host_addr: host address

        :returns: SCION address.
        :rtype: SCIONAddr
        """
        assert isinstance(host_addr, HostAddrBase)
        addr = cls()
        addr.isd_id = isd_id
        addr.ad_id = ad_id
        addr.host_addr = host_addr
        addr.addr_len = ISD_AD.LEN + len(addr.host_addr)
        return addr

    def parse(self, addr_type, raw):
        """
        Parse a raw byte string.

        :param int addr_type: Host address type
        :param bytes raw: raw bytes.
        """
        haddr_type = haddr_get_type(addr_type)
        self.addr_len = ISD_AD.LEN + haddr_type.LEN
        data = Raw(raw, "SCIONAddr (%s)" % haddr_type.NAME, self.addr_len)
        self.isd_id, self.ad_id = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.host_addr = haddr_type(data.pop(haddr_type.LEN))

    def pack(self):
        """
        Pack the class variables into a byte string.

        :returns: a byte string containing ISD ID, AD ID, and host address.
        :rtype: bytes
        """
        return ISD_AD(self.isd_id, self.ad_id).pack() + self.host_addr.pack()

    def __len__(self):
        return self.addr_len

    def __eq__(self, other):  # pragma: no cover
        return (
            self.isd_id == other.isd_id and
            self.ad_id == other.ad_id and
            self.host_addr == other.host_addr
        )

    def __str__(self):
        """
        Return a string containing ISD ID, AD ID, and host address.
        """
        return "(%u, %u, %s)" % (self.isd_id, self.ad_id, self.host_addr)

    def get_isd_ad(self):
        """
        Return a tuple containing ISD ID and AD ID.

        :returns: a tuple containing ISD ID and AD ID.
        :rtype: tuple
        """
        return ISD_AD(self.isd_id, self.ad_id)
