"""
opaque_field.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import logging
from bitstring import BitArray
import bitstring

class OpaqueFieldType(object):
    """
    Defines constants for the types of the opaque field (first byte of every
    opaque field, i.e. field).
    """
    NORMAL_OF = 0x00
    SPECIAL_OF = 0x80
    TDC_XOVR = 0x80
    NON_TDC_XOVR = 0xc0
    INPATH_XOVR = 0xe0
    INTRATD_PEER = 0xf0
    INTERTD_PEER = 0xf8
    PEER_XOVR = 0x10
    ROT_OF = 0xff

class OpaqueField(object):
    """
    Base class for the different kinds of opaque fields in SCION.
    """

    LEN = 8

    def __init__(self):
        self.info = 0 #TODO verify path.PathType in that context
        self.parsed = False
        self.raw = None

    def parse(self, raw):
        """
        Populates fields from a raw byte block.
        """
        pass

    def pack(self):
        """
        Returns opaque field as 8 byte binary string.
        """
        pass

    def __eq__(self, other):
        if type(other) is type(self):
            return True
        else:
            return False

    def __ne__(self, other):
        return not self == other

    def is_regular(self):
        """
        Returns true if opaque field is regular, false otherwise.
        """
        return not BitArray(bytes([self.info]))[0]

    def is_continue(self):
        """
        Returns true if continue bit is set, false otherwise.
        """
        return BitArray(bytes([self.info]))[1]

    def is_xovr(self):
        """
        Returns true if crossover point bit is set, false otherwise.
        """
        return BitArray(bytes([self.info]))[2]

    def __str__(self):
        pass

    def __repr__(self):
        return self.__str__()


class HopOpaqueField(OpaqueField):
    """
    Opaque field for a hop in a path of the SCION packet header.

    Each hop opaque field has a type (8 bits), ingress/egress interfaces
    (16 bits) and a MAC (24 bits) authenticating the opaque field.
    """

    def __init__(self, raw=None):
        OpaqueField.__init__(self)
        self.ingress_if = 0
        self.egress_if = 0
        self.mac = 0
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < HopOpaqueField.LEN:
            logging.warning("Data too short to parse hop opaque field: "
                "data len %u", dlen)
            return
        bits = BitArray(bytes=raw)
        (self.info, self.ingress_if, self.egress_if, self.mac) = \
            bits.unpack("uintbe:8, uintbe:16, uintbe:16, uintbe:24")

        self.parsed = True

    def pack(self):
        return bitstring.pack("uintbe:8, uintbe:16, uintbe:16, uintbe:24",
                              self.info, self.ingress_if, self.egress_if,
                              self.mac).bytes

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.ingress_if == other.ingress_if and
                    self.egress_if == other.egress_if and
                    self.mac == other.mac)
        else:
            return False

    def __str__(self):
        s = "[Hop OF type: %u, ingress if: %u, egress if: %u, mac: %x]" % (
            self.info, self.ingress_if, self.egress_if, self.mac)
        return s


class InfoOpaqueField(OpaqueField):
    """
    Class for the info opaque field.

    The info opaque field contains type info of the path (1 byte), an expiration
    timestamp (2 bytes), the ISD ID (2 byte), # hops for this path (1 byte) and
    a reserved section (2 bytes).
    """

    def __init__(self, raw=None):
        OpaqueField.__init__(self)
        self.timestamp = 0
        self.isd_id = 0
        self.hops = 0
        self.reserved = 0
        self.raw = raw

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < InfoOpaqueField.LEN:
            logging.warning("Data too short to parse info opaque field: "
                "data len %u", dlen)
            return
        bits = BitArray(bytes=raw)
        (self.info, self.timestamp, self.isd_id, self.hops, self.reserved) = \
            bits.unpack("uintbe:8, uintbe:16, uintbe:16, uintbe:8, uintbe:16")

        self.parsed = True

    def pack(self):
        #PSz: Should InfoOpaqueFIeld with raw==None pack to b'\x00'*8 ?
        if not self.raw:
            return b''
        return bitstring.pack("uintbe:8, uintbe:16, uintbe:16, uintbe:8,"
                              "uintbe:16", self.info, self.timestamp,
                              self.isd_id, self.hops, self.reserved).bytes

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.info == other.info and
                    self.timestamp == other.timestamp and
                    self.isd_id == other.isd_id and
                    self.hops == other.hops and
                    self.reserved == other.reserved)
        else:
            return False

    def __str__(self):
        s = "[Info OF info: %x, TS: %u, ISD ID: %u, hops: %u]" % (
            self.info, self.timestamp, self.isd_id, self.hops)
        return s
