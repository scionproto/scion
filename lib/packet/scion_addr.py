#scion_addr.py

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
:mod:`scion_addr` --- SCION host address specifications
======================================================

Module docstring here.

.. note::
    Fill in the docstring.
"""

from bitstring import BitArray
import bitstring
from collections import namedtuple
from ipaddress import IPv4Address, IPv6Address, IPV4LENGTH, IPV6LENGTH
import logging
import socket
import struct


ISD_AD = namedtuple('ISD_AD', ['isd', 'ad'])


class SCIONAddr(object):
    """
    Class for complete SCION addresses.
    """
    ISD_AD_LEN = 10  # Size of (isd_id, ad_id) pair in bytes.

    def __init__(self, raw=None):
        self.isd_id = None
        self.ad_id = None
        self.host_addr = None
        self.addr_len = 0
        if raw:
            self.parse(raw)

    @classmethod
    def from_values(cls, isd_id, ad_id, host_addr):
        addr = SCIONAddr()
        addr.isd_id = isd_id
        addr.ad_id = ad_id
        addr.host_addr = host_addr
        if addr.host_addr.version == 4:
            host_addr_len = IPV4LENGTH // 8
        elif addr.host_addr.version == 6:
            host_addr_len = IPV6LENGTH // 8
        addr.addr_len = SCIONAddr.ISD_AD_LEN + host_addr_len
        return addr

    def parse(self, raw):
        assert isinstance(raw, bytes)
        addr_len = len(raw)
        if addr_len < SCIONAddr.ISD_AD_LEN:
            logging.warning("SCIONAddr: Data too short for parsing, len: %u",
                             addr_len)
            return
        bits = BitArray(bytes=raw[:SCIONAddr.ISD_AD_LEN])
        (self.isd_id, self.ad_id) = bits.unpack("uintbe:16, uintbe:64")
        host_addr_len = addr_len - SCIONAddr.ISD_AD_LEN
        if host_addr_len == IPV4LENGTH // 8: 
            self.host_addr = IPv4Address(raw[SCIONAddr.ISD_AD_LEN:])
        elif host_addr_len == IPV6LENGTH // 8: 
            self.host_addr = IPv6Address(raw[SCIONAddr.ISD_AD_LEN:])
        else:
            logging.warning("SCIONAddr: host address unsupported, len: %u",
                            host_addr_len)
            return
        self.addr_len = SCIONAddr.ISD_AD_LEN + host_addr_len

    def pack(self):
        return (bitstring.pack("uintbe:16, uintbe:64", self.isd_id,
                               self.ad_id).bytes + self.host_addr.packed)

    def __str__(self):
        return "(%u, %u, %s)" % (self.isd_id, self.ad_id, self.host_addr)

    def get_isd_ad(self):
        return ISD_AD(self.isd_id, self.ad_id)

