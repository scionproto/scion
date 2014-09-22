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
    Defines constants for the types of the opaque field.
    """
    INFO_OF = 0
    HOP_OF = 1


class OpaqueField(object):
    """
    Base class for the different kinds of opaque fields in SCION.
    """

    LEN = 8

    def __init__(self):
        self.type = OpaqueFieldType.INFO_OF
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
            return self.type == other.type
        else:
            return False

    def __ne__(self, other):
        return not self == other

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

    LEN = 8

    def __init__(self, raw=None):
        OpaqueField.__init__(self)
        self.type = OpaqueFieldType.HOP_OF
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
        (self.type, self.ingress_if, self.egress_if, self.mac) = \
            bits.unpack("uintle:8, uintle:16, uintle:16, uintle:24")

        self.parsed = True

    def pack(self):
        return bitstring.pack("uintle:8, uintle:16, uintle:16, uintle:24",
                              self.type, self.ingress_if, self.egress_if,
                              self.mac).bytes

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.type == other.type and
                    self.ingress_if == other.ingress_if and
                    self.egress_if == other.egress_if and
                    self.mac == other.mac)
        else:
            return False

    def __str__(self):
        s = "[Hop OF type: %u, ingress if: %u, egress if: %u, mac: %x]" % (
            self.type, self.ingress_if, self.egress_if, self.mac)
        return s


class InfoOpaqueField(OpaqueField):
    """
    Class for the info opaque field.

    The info opaque field contains type info of the path (1 byte), an expiration
    timestamp (2 bytes), the ISD ID (2 byte), # hops for this path (1 byte) and
    a reserved section (2 bytes).
    """

    LEN = 8

    def __init__(self, raw=None):
        OpaqueField.__init__(self)
        self.type = OpaqueFieldType.INFO_OF
        self.info = 0  # FIXME: Add constants for this info field.
        self.timestamp = 0
        self.isd_id = 0
        self.hops = 0
        self.reserved = 0

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
        (self.info, self.timestamp, self.isd_id, self.hops, _reserved) = \
            bits.unpack("uintle:8, uintle:16, uintle:16, uintle:8, uintle:16")

        self.parsed = True

    def pack(self):
        return bitstring.pack("uintle:8, uintle:16, uintle:16, uintle:8,"
                              "uintle:16", self.info, self.timestamp,
                              self.isd_id, self.hops, self.reserved).bytes

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.type == other.type and
                    self.info == other.info and
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
