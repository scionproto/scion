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
:mod:`opaque_field` --- SCION Opaque fields
===========================================
"""
# Stdlib
import logging
import struct


class OpaqueFieldType(object):
    """
    Defines constants for the types of the opaque field (first byte of every
    opaque field, i.e. field).
    TODO describe here layout of Opaque Fields
    """
    # Types for HopOpaqueFields (7 MSB bits).
    NORMAL_OF = 0b0000000
    LAST_OF = 0b0010000  # indicates last hop OF on the half-path (TODO revise)
    PEER_XOVR = 0b0001000
    # Types for Info Opaque Fields (7 MSB bits).
    TDC_XOVR = 0b1000000
    NON_TDC_XOVR = 0b1100000
    INPATH_XOVR = 0b1110000
    INTRATD_PEER = 0b1111000
    INTERTD_PEER = 0b1111100


class OpaqueField(object):
    """
    Base class for the different kinds of opaque fields in SCION.
    """
    LEN = 8

    def __init__(self):
        """
        Initialize an instance of the class OpaqueField.
        """
        self.info = 0  # TODO verify path.PathType in that context
        self.type = 0
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

    def is_regular(self):
        """
        Returns true if opaque field is regular, false otherwise.
        """
        return (self.info & (1 << 6) == 0)

    def is_continue(self):
        """
        Returns true if continue bit is set, false otherwise.
        """
        return not (self.info & (1 << 5) == 0)

    def is_xovr(self):
        """
        Returns true if crossover point bit is set, false otherwise.
        """
        return not (self.info & (1 << 4) == 0)

    def __str__(self):
        pass

    def __repr__(self):
        return self.__str__()

    # TODO test: one __eq__ breaks router when two SOFs in a path are identical
    def __eq__(self, other):
        if type(other) is type(self):
            return self.raw == other.raw
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)


class HopOpaqueField(OpaqueField):
    """
    Opaque field for a hop in a path of the SCION packet header.

    Each hop opaque field has a info (8 bits), expiration time (8 bits)
    ingress/egress interfaces (2 * 12 bits) and a MAC (24 bits) authenticating
    the opaque field.
    """
    MAC_LEN = 3  # MAC length in bytes.

    def __init__(self, raw=None):
        """
        Initialize an instance of the class HopOpaqueField.

        :param raw:
        :type raw:
        """
        OpaqueField.__init__(self)
        self.exp_time = 0
        self.ingress_if = 0
        self.egress_if = 0
        self.mac = b"\x00" * self.MAC_LEN
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw byte block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.LEN:
            logging.warning("HOF: Data too short for parsing, len: %u", dlen)
            return
        (self.info, self.exp_time) = struct.unpack("!BB", raw[:2])
        # A byte added as length of three bytes can't be unpacked
        (ifs,) = struct.unpack("!I", b'\0' + raw[2:5])
        self.mac = raw[5:8]
        self.ingress_if = (ifs & 0xFFF000) >> 12
        self.egress_if = ifs & 0x000FFF
        self.parsed = True

    @classmethod
    def from_values(cls, exp_time, ingress_if=0, egress_if=0, mac=None):
        """
        Returns HopOpaqueField with fields populated from values.

        @param exp_time: Expiry time. An integer in the range [0,255]
        @param ingress_if: Ingress interface.
        @param egress_if: Egress interface.
        @param mac: MAC of ingress/egress interfaces' ID and timestamp.
        """
        hof = HopOpaqueField()
        hof.exp_time = exp_time
        hof.ingress_if = ingress_if
        hof.egress_if = egress_if
        if mac is None:
            mac = b"\x00" * cls.MAC_LEN
        hof.mac = mac
        return hof

    def pack(self):
        """
        Returns HopOpaqueField as 8 byte binary string.
        """
        ifs = (self.ingress_if << 12) | self.egress_if
        data = struct.pack("!BB", self.info, self.exp_time)
        # Ingress and egress interface info is packed into three bytes
        data += struct.pack("!I", ifs)[1:]
        data += self.mac
        return data

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.exp_time == other.exp_time and
                    self.ingress_if == other.ingress_if and
                    self.egress_if == other.egress_if and
                    self.mac == other.mac)
        else:
            return False

    def __str__(self):
        hof_str = ("[Hop OF info: %u, exp_time: %d, ingress if: %u, "
                   "egress if: %u, mac: %s]" % (
                       self.info, self.exp_time, self.ingress_if,
                       self.egress_if, self.mac))
        return hof_str


class InfoOpaqueField(OpaqueField):
    """
    Class for the info opaque field.

    The info opaque field contains type info of the path-segment (1 byte),
    a creation timestamp (4 bytes), the ISD ID (2 byte) and # hops for this
    segment (1 byte).
    """

    def __init__(self, raw=None):
        """
        Initialize an instance of the class InfoOpaqueField.

        :param raw:
        :type raw:
        """
        OpaqueField.__init__(self)
        self.timestamp = 0
        self.isd_id = 0
        self.hops = 0
        self.up_flag = False
        self.raw = raw
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw byte block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < self.LEN:
            logging.warning("IOF: Data too short for parsing, len: %u", dlen)
            return
        (self.info, self.timestamp, self.isd_id, self.hops) = \
            struct.unpack("!BIHB", raw)

        self.up_flag = bool(self.info & 0b00000001)
        self.info >>= 1
        self.parsed = True

    @classmethod
    def from_values(cls, info=0, up_flag=False, timestamp=0, isd_id=0, hops=0):
        """
        Returns InfoOpaqueField with fields populated from values.

        @param info: Opaque field type.
        @param up_flag: up/down-flag.
        @param timestamp: Beacon's timestamp.
        @param isd_id: Isolation Domanin's ID.
        @param hops: Number of hops in the segment.
        """
        iof = InfoOpaqueField()
        iof.info = info
        iof.up_flag = up_flag
        iof.timestamp = timestamp
        iof.isd_id = isd_id
        iof.hops = hops
        return iof

    def pack(self):
        """
        Returns InfoOpaqueFIeld as 8 byte binary string.
        """
        info = (self.info << 1) + self.up_flag
        data = struct.pack("!BIHB", info, self.timestamp, self.isd_id,
                           self.hops)
        return data

    def __str__(self):
        iof_str = ("[Info OF info: %x, up: %r, TS: %u, ISD ID: %u, hops: %u]" %
                   (self.info, self.up_flag, self.timestamp, self.isd_id,
                    self.hops))
        return iof_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.info == other.info and
                    self.up_flag == other.up_flag and
                    self.timestamp == other.timestamp and
                    self.isd_id == other.isd_id and
                    self.hops == other.hops)
        else:
            return False
