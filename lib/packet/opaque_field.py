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
    ROT_OF = 0b11111111


class OpaqueField(object):
    """
    Base class for the different kinds of opaque fields in SCION.
    """
    LEN = 8

    def __init__(self):
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
        return not BitArray(bytes([self.info]))[1]

    def is_continue(self):
        """
        Returns true if continue bit is set, false otherwise.
        """
        return BitArray(bytes([self.info]))[2]

    def is_xovr(self):
        """
        Returns true if crossover point bit is set, false otherwise.
        """
        return BitArray(bytes([self.info]))[3]

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
    def __init__(self, raw=None):
        OpaqueField.__init__(self)
        self.exp_time = 0
        self.ingress_if = 0
        self.egress_if = 0
        self.mac = 0
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw byte block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < HopOpaqueField.LEN:
            logging.warning("HOF: Data too short for parsing, len: %u", dlen)
            return
        bits = BitArray(bytes=raw)
        (self.info, self.exp_time, ifs, self.mac) = bits.unpack("uintbe:8, " +
            "uintbe:8, uintbe:24, uintbe:24")
        self.ingress_if = (ifs & 0xFFF000) >> 12
        self.egress_if = ifs & 0x000FFF
        self.parsed = True

    @classmethod
    def from_values(cls, exp_time, ingress_if=0, egress_if=0, mac=0):
        """
        Returns HopOpaqueField with fields populated from values.

        @param ingress_if: Ingress interface.
        @param egress_if: Egress interface.
        @param mac: MAC of ingress/egress interfaces' ID and timestamp.
        """
        hof = HopOpaqueField()
        hof.exp_time = exp_time
        hof.ingress_if = ingress_if
        hof.egress_if = egress_if
        hof.mac = mac
        return hof

    def pack(self):
        """
        Returns HopOpaqueField as 8 byte binary string.
        """
        ifs = (self.ingress_if << 12) | self.egress_if
        return bitstring.pack("uintbe:8, uintbe:8, uintbe:24, uintbe:24",
                              self.info, self.exp_time, ifs, self.mac).bytes

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.exp_time == other.exp_time and
                    self.ingress_if == other.ingress_if and
                    self.egress_if == other.egress_if and
                    self.mac == other.mac)
        else:
            return False

    def __str__(self):
        hof_str = (("[Hop OF info: %u, exp_time: %d, ingress if: %u, " +
                    "egress if: %u, mac: %x]") % (self.info, self.exp_time,
                      self.ingress_if, self.egress_if, self.mac))
        return hof_str


class InfoOpaqueField(OpaqueField):
    """
    Class for the info opaque field.

    The info opaque field contains type info of the path-segment (1 byte),
    a creation timestamp (4 bytes), the ISD ID (2 byte) and # hops for this
    segment (1 byte).
    """

    def __init__(self, raw=None):
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
        if dlen < InfoOpaqueField.LEN:
            logging.warning("IOF: Data too short for parsing, len: %u", dlen)
            return
        bits = BitArray(bytes=raw)
        (self.info, self.timestamp, self.isd_id, self.hops) = \
            bits.unpack("uintbe:8, uintbe:32, uintbe:16, uintbe:8")
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
        return bitstring.pack("uintbe:8, uintbe:32, uintbe:16, uintbe:8",
            info, self.timestamp, self.isd_id, self.hops).bytes

    def __str__(self):
        iof_str = ("[Info OF info: %x, up: %r, TS: %u, ISD ID: %u, hops: %u]" %
            (self.info, self.up_flag, self.timestamp, self.isd_id, self.hops))
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


class ROTField(OpaqueField):
    """
    Class for the ROT field.

    The ROT field contains type info of the path-segment (1 byte),
    the ROT version (4 bytes), the IF ID (2 bytes),
    and a reserved section (1 byte).
    """
    def __init__(self, raw=None):
        OpaqueField.__init__(self)
        self.info = OpaqueFieldType.ROT_OF
        self.rot_version = 0
        self.if_id = 0
        self.reserved = 0
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw byte block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < ROTField.LEN:
            logging.warning("ROTF: Data too short for parsing, len: %u", dlen)
            return
        bits = BitArray(bytes=raw)
        (self.info, self.rot_version, self.if_id, self.reserved) = \
            bits.unpack("uintbe:8, uintbe:32, uintbe:16, uintbe:8")
        self.parsed = True

    @classmethod
    def from_values(cls, rot_version=0, if_id=0, reserved=0):
        """
        Returns ROTField with fields populated from values.

        @param rot_version: Version of the Isolation Domanin's ROT file.
        @param if_id: Interface ID.
        @param reserved: Reserved section.
        """
        rotf = ROTField()
        rotf.rot_version = rot_version
        rotf.if_id = if_id
        rotf.reserved = reserved
        return rotf

    def pack(self):
        """
        Returns ROTField as 8 byte binary string.
        """
        return bitstring.pack("uintbe:8, uintbe:32, uintbe:16, uintbe:8",
            self.info, self.rot_version, self.if_id, self.reserved).bytes

    def __str__(self):
        rotf_str = ("[ROT OF info: %x, ROTv: %u, IF ID: %u]\n" %
            (self.info, self.rot_version, self.if_id))
        return rotf_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.info == other.info and
                    self.rot_version == other.rot_version and
                    self.if_id == other.if_id)
        else:
            return False


class SupportSignatureField(OpaqueField):
    """
    Class for the support signature field.

    The support signature field contains a certificate ID (4 bytes), the
    signature length (2 bytes), and the block size (2 bytes).
    """
    def __init__(self, raw=None):
        OpaqueField.__init__(self)
        self.cert_id = 0
        self.sig_len = 0
        self.block_size = 0
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw byte block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < SupportSignatureField.LEN:
            logging.warning("SSF: Data too short for parsing, len: %u", dlen)
            return
        bits = BitArray(bytes=raw)
        (self.cert_id, self.sig_len, self.block_size) = \
            bits.unpack("uintbe:32, uintbe:16, uintbe:16")
        self.parsed = True

    @classmethod
    def from_values(cls, block_size, cert_id=0, sig_len=0):
        """
        Returns SupportSignatureField with fields populated from values.

        @param block_size: Total marking size for an AD block (peering links
            included.)
        @param cert_id: ID of the Autonomous Domain's certificate.
        @param sig_len: Length of the beacon's signature.
        """
        ssf = SupportSignatureField()
        ssf.cert_id = cert_id
        ssf.sig_len = sig_len
        ssf.block_size = block_size
        return ssf

    def pack(self):
        """
        Returns SupportSignatureField as 8 byte binary string.
        """
        return bitstring.pack("uintbe:32, uintbe:16, uintbe:16", self.cert_id,
                              self.sig_len, self.block_size).bytes

    def __str__(self):
        ssf_str = ("[Support Signature OF cert_id: %x, sig_len: %u, " +
            "block_size: %u]\n") % (self.cert_id, self.sig_len, self.block_size)
        return ssf_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.cert_id == other.cert_id and
                    self.sig_len == other.sig_len and
                    self.block_size == other.block_size)
        else:
            return False


class SupportPeerField(OpaqueField):
    """
    Class for the support peer field.

    The support peer field contains the trusted domain id (2 bytes),
    bandwidth allocation left (1 byte), bandwith allocation right (1 byte),
    the bandwidth class (1 bit), and a reserved section (31 bits).
    """
    def __init__(self, raw=None):
        OpaqueField.__init__(self)
        self.isd_id = 0
        self.bwalloc_f = 0
        self.bwalloc_r = 0
        self.bw_class = 0
        self.reserved = 0
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw byte block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < SupportPeerField.LEN:
            logging.warning("SPF: Data too short for parsing, len: %u", dlen)
            return
        bits = BitArray(bytes=raw)
        (self.isd_id, self.bwalloc_f, self.bwalloc_r, self.bw_class,
            self.reserved) = bits.unpack("uintbe:16, uintbe:8, uintbe:8, "
                                         "uint:1, uint:31")
        self.parsed = True

    @classmethod
    def from_values(cls, isd_id=0,
                    bwalloc_f=0, bwalloc_r=0,
                    bw_class=0, reserved=0):
        """
        Returns SupportPeerField with fields populated from values.

        @param isd_id: Isolation Domanin's ID.
        @param bwalloc_f: Allocated bandwidth left.
        @param bwalloc_r: Allocated bandwidth right.
        @param bw_class: Bandwidth class.
        @param reserved: Reserved section.
        """
        spf = SupportPeerField()
        spf.isd_id = isd_id
        spf.bwalloc_f = bwalloc_f
        spf.bwalloc_r = bwalloc_r
        spf.bw_class = bw_class
        spf.reserved = reserved
        return spf

    def pack(self):
        """
        Returns SupportPeerField as 8 byte binary string.
        """
        return bitstring.pack("uintbe:16, uintbe:8, uintbe:8, uint:1, uint:31",
            self.isd_id, self.bwalloc_f, self.bwalloc_r, self.bw_class,
            self.reserved).bytes

    def __str__(self):
        spf_str = ("[Support Peer OF TD ID: %x, bwalloc_f: %u, " +
            "bwalloc_r: %u, bw_class: %u]\n") % (self.isd_id, self.bwalloc_f,
            self.bwalloc_r, self.bw_class)
        return spf_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.isd_id == other.isd_id and
                    self.bwalloc_f == other.bwalloc_f and
                    self.bwalloc_r == other.bwalloc_r and
                    self.bw_class == other.bw_class)
        else:
            return False


class SupportPCBField(OpaqueField):
    """
    Class for the support PCB field.

    The support PCB field contains the trusted domain id (2 bytes),
    bandwidth allocation left (1 byte), bandwith allocation right (1 byte),
    dynamic bandwidth allocation left (1 byte), dynamic bandwidth allocation
    right (1 byte), best effort bandwidth left (1 byte), and best effort
    bandwidth right (1 byte).
    """
    def __init__(self, raw=None):
        OpaqueField.__init__(self)
        self.isd_id = 0
        self.bwalloc_f = 0
        self.bwalloc_r = 0
        self.dyn_bwalloc_f = 0
        self.dyn_bwalloc_r = 0
        self.bebw_f = 0
        self.bebw_r = 0
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw byte block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < SupportPCBField.LEN:
            logging.warning("SPCBF: Data too short for parsing, len: %u", dlen)
            return
        bits = BitArray(bytes=raw)
        (self.isd_id, self.bwalloc_f, self.bwalloc_r, self.dyn_bwalloc_f,
            self.dyn_bwalloc_r, self.bebw_f, self.bebw_r) = \
            bits.unpack("uintbe:16, uintbe:8, uintbe:8, uintbe:8, uintbe:8, "
                        "uintbe:8, uintbe:8")
        self.parsed = True

    @classmethod
    def from_values(cls, isd_id=0, bwalloc_f=0, bwalloc_r=0, dyn_bwalloc_f=0,
                    dyn_bwalloc_r=0, bebw_f=0, bebw_r=0):
        """
        Returns SupportPCBField with fields populated from values.

        @param isd_id: Isolation Domanin's ID.
        @param bwalloc_f: Allocated bandwidth left.
        @param bwalloc_r: Allocated bandwidth right.
        @param dyn_bwalloc_f: Dynamic allocated bandwidth left.
        @param dyn_bwalloc_r: Dynamic allocated bandwidth right.
        @param bebw_f: Best effort bandwidth left.
        @param bebw_r: Best effort bandwidth right.
        """
        spcbf = SupportPCBField()
        spcbf.isd_id = isd_id
        spcbf.bwalloc_f = bwalloc_f
        spcbf.bwalloc_r = bwalloc_r
        spcbf.dyn_bwalloc_f = dyn_bwalloc_f
        spcbf.dyn_bwalloc_r = dyn_bwalloc_r
        spcbf.bebw_f = bebw_f
        spcbf.bebw_r = bebw_r
        return spcbf

    def pack(self):
        """
        Returns SupportPCBField as 8 byte binary string.
        """
        return bitstring.pack("uintbe:16, uintbe:8, uintbe:8, uintbe:8, "
            "uintbe:8, uintbe:8, uintbe:8", self.isd_id, self.bwalloc_f,
            self.bwalloc_r, self.dyn_bwalloc_f, self.dyn_bwalloc_r, self.bebw_f,
            self.bebw_r).bytes

    def __str__(self):
        spcbf_str = ("[Info OF TD ID: %x, bwalloc_f: %u, bwalloc_r: %u]\n" %
            (self.isd_id, self.bwalloc_f, self.bwalloc_r))
        return spcbf_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.isd_id == other.isd_id and
                    self.bwalloc_f == other.bwalloc_f and
                    self.bwalloc_r == other.bwalloc_r and
                    self.dyn_bwalloc_f == other.dyn_bwalloc_f and
                    self.dyn_bwalloc_r == other.dyn_bwalloc_f and
                    self.bebw_f == other.bebw_f and
                    self.bebw_r == other.bebw_r)
        else:
            return False
