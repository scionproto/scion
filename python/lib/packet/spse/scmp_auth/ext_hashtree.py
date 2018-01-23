# Copyright 2017 ETH Zurich
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
:mod:`extn` --- SCMPAuthDRKey and SCMPAuthHashTree extension header
=================================================================
"""
# Stdlib
import struct

# SCION
from lib.packet.spse.defines import (
    SPSEValidationError,
    SPSELengths,
    SPSESecModes,
)
from lib.packet.spse.ext import SCIONPacketSecurityBaseExtn
from lib.util import hex_str, Raw


class SCMPAuthHashtreeLengths:
    """
    Constant lengths.
    """
    HASH = 16
    HEIGHT = 1
    RESERVED = 1
    ORDER = 2
    SIGNATURE = 64
    HASH_TREE_MIN_LENGTH = SPSELengths.SECMODE + HEIGHT + RESERVED + ORDER + SIGNATURE


class SCMPAuthHashTreeExtn(SCIONPacketSecurityBaseExtn):
    """
    Implementation of the SCMPAuthHashTree extension, which is based on the
    SCIONPacketSecurity extension.

    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx |  0x05  | Height |reserved|      Order      |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                          Signature (8 lines)                          |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                         Hashes (height * 2 lines)                     |
    +--------+--------+--------+--------+--------+--------+--------+--------+

    Height: Height of the hash tree. MAX_HEIGHT is 24.
    Order: Bit vector. The bit at index i is associated with hash i.
        0 (1) indicates hash i shall be used as left (right) input.
    Signature: Signature of resulting hash
    Hashes: Hashes used to verify the proof. At index 0 is the leaf hash, at
        index height is the root hash.
    """
    NAME = "SCMPAuthHashTreeExtn"
    # max height of the hash tree
    MAX_HEIGHT = 16

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param bytes raw: Raw data holding height, order, signature and hashes.
        """
        self.height = 0
        self.order = b""
        self.signature = b""
        self.hashes = b""
        super().__init__(raw)

    def _parse(self, raw):
        """
        Parse payload to extract values.

        :param bytes raw: raw payload.
        """
        data = Raw(raw, self.NAME)
        super()._parse(data)

        self.sec_mode = data.pop(SPSELengths.SECMODE)
        self.height = data.pop(SCMPAuthHashtreeLengths.HEIGHT)
        data.pop(SCMPAuthHashtreeLengths.RESERVED)
        self.order = data.pop(SCMPAuthHashtreeLengths.ORDER)
        self.signature = data.pop(SCMPAuthHashtreeLengths.SIGNATURE)
        self.hashes = data.pop(self.height * SCMPAuthHashtreeLengths.HASH)

    @classmethod
    def from_values(cls, height, order, signature, hashes):  # pragma: no cover
        """
        Construct extension.

        :param int height: Height of the hash tree.
        :param bytes order: bit vector indicating left or right hash.
        :param bytes signature: Signature of the resulting hash.
        :param bytes hashes: Hashes needed to conduct the proof.
        :returns: The created instance.
        :rtype: SCMPAuthHashTreeExtn
        :raises: SPSEValidationError
        """
        cls.check_validity(height, order, signature, hashes)

        inst = cls()
        inst.sec_mode = SPSESecModes.SCMP_AUTH_HASH_TREE
        inst.height = height
        inst.order = order
        inst.signature = signature
        inst.hashes = hashes
        hdr_len = inst.bytes_to_hdr_len(
            SCMPAuthHashtreeLengths.HASH_TREE_MIN_LENGTH +
            height * SCMPAuthHashtreeLengths.HASH)
        inst._init_size(hdr_len-1)
        return inst

    def pack(self):
        """
        Pack extension into byte string

        :returns: packed extension.
        :rtype: bytes
        """
        packed = [struct.pack("!B", self.sec_mode),
                  struct.pack("!B", self.height),
                  bytes(SCMPAuthHashtreeLengths.RESERVED),
                  self.order,
                  self.signature,
                  self.hashes]
        raw = b"".join(packed)
        self._check_len(raw)
        return raw

    @classmethod
    def check_validity(cls, height, order, signature, hashes):
        """
        Check if parameters are valid

        :param int height: Height of the hash tree.
        :param bytes order: bit vector indicating left or right hash.
        :param bytes signature: Signature of the resulting hash.
        :param bytes hashes: Hashes needed to conduct the proof.
        :raises: SPSEValidationError
        """

        if not 0 <= height <= cls.MAX_HEIGHT:
            raise SPSEValidationError("Invalid height %s. Max height %s" % (
                height, cls.MAX_HEIGHT))
        if len(order) != SCMPAuthHashtreeLengths.ORDER:
            raise SPSEValidationError("Invalid order length %sB. Expected %sB" % (
                len(order), SCMPAuthHashtreeLengths.ORDER))
        if len(signature) != SCMPAuthHashtreeLengths.SIGNATURE:
            raise SPSEValidationError("Invalid signature length %sB. Expected %sB" % (
                len(signature), SCMPAuthHashtreeLengths.SIGNATURE))
        if len(hashes) != height * SCMPAuthHashtreeLengths.HASH:
            raise SPSEValidationError("Invalid hashes length %sB. Expected %sB" % (
                len(hashes), height * SCMPAuthHashtreeLengths.HASH))

    def __str__(self):
        return ("%s(%sB): Height: %s Order: %s\n\tSignature: %s\n\tHashes: %s" % (
                 self.NAME, len(self), self.height, hex_str(self.order),
                 hex_str(self.signature), hex_str(self.hashes)))
