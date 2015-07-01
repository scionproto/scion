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
import logging
import struct
from collections import namedtuple
from ipaddress import IPV4LENGTH, IPV6LENGTH, IPv4Address, IPv6Address


class ISD_AD(namedtuple('ISD_AD', 'isd ad')):
    """
    Class for representing isd,ad pair.

    :ivar isd: ISD identifier.
    :type isd: int
    :ivar ad: AD identifier.
    :type ad: int
    """
    LEN = 4

    @classmethod
    def from_raw(cls, raw):
        """
        Create an instance of the class ISD_AD.

        :param raw: a byte string containing ISD ID, AD ID. ISD and AD are
                    respectively represented as 12 and 20 most significant bits.
        :type isd_id: bytes

        :returns: ISD, AD tuple.
        :rtype: :class:`ISD_AD`
        """
        isd_ad = struct.unpack("!I", raw)[0]
        isd = isd_ad >> 20
        ad = isd_ad & 0x000fffff
        return ISD_AD(isd, ad)

    def pack(self):
        """
        Pack the class variables into a byte string.

        :returns: a 4B long byte string containing ISD ID (first 12 bits),
                  AD ID (remaining 20 bits).
        :rtype: bytes
        """
        isd = self.isd << 20
        ad = self.ad & 0x000fffff
        return struct.pack("!I", isd + ad)


class SCIONAddr(object):
    """
    Class for complete SCION addresses.

    :ivar isd_id: ISD identifier.
    :type isd_id: int
    :ivar ad_id: AD identifier.
    :type ad_id: int
    :ivar host_addr: host address.
    :type host_addr: IPv4Address or IPv6Address
    :ivar addr_len: address length.
    :type addr_len: int
    """

    def __init__(self, raw=None):
        """
        Initialize an instance of the class SCIONAddr.

        :param raw: raw bytes.
        :type raw: bytes
        """
        self.isd_id = None
        self.ad_id = None
        self.host_addr = None
        self.addr_len = 0
        if raw:
            self.parse(raw)

    @classmethod
    def from_values(cls, isd_id, ad_id, host_addr):
        """
        Create an instance of the class SCIONAddr.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :param host_addr: host IP addresses.
        :type host_addr: IPv4Address or IPv6Address

        :returns: SCION address.
        :rtype: :class:`SCIONAddr`
        """
        addr = SCIONAddr()
        addr.isd_id = isd_id
        addr.ad_id = ad_id
        addr.host_addr = host_addr
        if addr.host_addr.version == 4:
            host_addr_len = IPV4LENGTH // 8
        elif addr.host_addr.version == 6:
            host_addr_len = IPV6LENGTH // 8
        addr.addr_len = ISD_AD.LEN + host_addr_len
        return addr

    def parse(self, raw):
        """
        Parse a raw byte string.

        :param raw: raw bytes.
        :type raw: bytes
        """
        assert isinstance(raw, bytes)
        addr_len = len(raw)
        if addr_len < ISD_AD.LEN:
            logging.warning("SCIONAddr: Data too short for parsing, len: %u",
                            addr_len)
            return
        (self.isd_id, self.ad_id) = ISD_AD.from_raw(raw[:ISD_AD.LEN])
        host_addr_len = addr_len - ISD_AD.LEN
        if host_addr_len == IPV4LENGTH // 8:
            self.host_addr = IPv4Address(raw[ISD_AD.LEN:])
        elif host_addr_len == IPV6LENGTH // 8:
            self.host_addr = IPv6Address(raw[ISD_AD.LEN:])
        else:
            logging.warning("SCIONAddr: host address unsupported, len: %u",
                            host_addr_len)
            return
        self.addr_len = ISD_AD.LEN + host_addr_len

    def pack(self):
        """
        Pack the class variables into a byte string.

        :returns: a byte string containing ISD ID, AD ID, and host address.
        :rtype: bytes
        """
        return ISD_AD(self.isd_id, self.ad_id).pack() + self.host_addr.packed

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
