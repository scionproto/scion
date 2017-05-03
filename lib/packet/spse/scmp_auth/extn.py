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
from lib.packet.ext_hdr import EndToEndExtension
from lib.packet.spse.defines import (
    SPSEBaseError,
    SPSELengths,
    SPSESecModes,
)
from lib.packet.spse.scmp_auth.defines import (
    SCMPAuthDirections,
    SCMPAuthLengths,
    MAX_HEIGHT
)
from lib.types import ExtEndToEndType
from lib.util import hex_str, Raw


class SCMPAuthDRKeyExtn(EndToEndExtension):
    """
    Implementation of the SCMPAuthDRKey extension, which is based on the
    SCIONPacketSecurity extension.

    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx |  0x04  |  dir   |         padding          |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                              DRKey MAC                                |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                              DRKey MAC (continued)                    |
    +--------+--------+--------+--------+--------+--------+--------+--------+

    Dir: indicates which key was used to authenticate i.e. create the MAC.
         Values are defined in SCMPAuthDirections.
    MAC: MAC over whole spkt with CurrHF and CurrINF set to zero.
    """
    NAME = "SCMPAuthDRKeyExtn"
    EXT_TYPE = ExtEndToEndType.SCION_PACKET_SECURITY

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param bytes raw: Raw data holding direction and mac.
        """
        self.sec_mode = SPSESecModes.SCMP_AUTH_DRKEY
        self.direction = 0
        self.mac = []
        super().__init__(raw)

    def _parse(self, raw):
        """
        Parse payload to extract values.

        :param bytes raw: raw payload.
        """
        data = Raw(raw, self.NAME)
        super()._parse(data)

        self.sec_mode = data.pop(SPSELengths.SECMODE)
        self.direction = data.pop(SCMPAuthLengths.DIRECTION)
        data.pop(SCMPAuthLengths.PADDING)
        self.mac = data.pop(SCMPAuthLengths.MAC)

    @classmethod
    def from_values(cls, direction, mac=None):  # pragma: no cover
        """
        Construct extension.

        :param int direction: Indicates which key was used for authentication.
        :param bytes mac: The mac of the extension. If None set to all zeros.
        :returns: The created instance.
        :rtype: SCMPAuthDRKeyExtn
        :raises: SPSEBaseError
        """
        error = cls.check_validity(direction, mac)
        if error:
            raise error

        inst = cls()
        inst._init_size(inst.bytes_to_hdr_len(
            SCMPAuthLengths.DRKEY_TOTAL_LENGTH))
        inst.direction = direction
        inst.mac = mac if mac else bytes(SCMPAuthLengths.MAC)
        return inst

    def pack(self):
        """
        Pack extension into byte string

        :returns: packed extension.
        :rtype: bytes
        """
        packed = [struct.pack("!B", self.sec_mode),
                  struct.pack("!B", self.direction),
                  bytes(SCMPAuthLengths.PADDING),
                  self.mac]
        raw = b"".join(packed)
        self._check_len(raw)
        return raw

    @staticmethod
    def check_validity(direction, mac):
        """
        Check if parameters are valid.

        :param int direction: Indicates which key was used for authentication.
        :param bytes mac: The mac of the extension.
        :returns: An error if invalid parameters, None otherwise.
        :rtype: SPSEBaseError
        """

        if not SCMPAuthDirections.is_valid_direction(direction):
            return SPSEBaseError("Invalid direction %s" % direction)
        if mac and not len(mac) == SCMPAuthLengths.MAC:
            return SPSEBaseError("Invalid mac length %s. Expected %s" % (
                len(mac), SCMPAuthLengths.MAC))
        return None

    def __str__(self):
        return "%s(%sB):\n\tDirection: %s\n\tMAC: %s" % (
            self.NAME, len(self), self.direction,
            hex_str(self.mac))


class SCMPAuthHashTreeExtn(EndToEndExtension):
    """
    Implementation of the SCMPAuthHashTree extension, which is based on the
    SCIONPacketSecurity extension.

    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx |  0x05  | Height |            Order         |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                               Signature (8 lines)                     |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                               Hashes (height * 2)                     |
    +--------+--------+--------+--------+--------+--------+--------+--------+

    Height: Height of the hash tree. MAX_HEIGHT is 24.
    Order: Bit vector. The bit at index i is associated with hash i.
        0 (1) indicates hash i shall be used as left (right) input.
    Signature: Signature of resulting hash
    Hashes: Hashes used to verify the proof. At index 0 is the leaf hash, at
        index height is the root hash.
    """
    NAME = "SCMPAuthHashTreeExtn"
    EXT_TYPE = ExtEndToEndType.SCION_PACKET_SECURITY

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param bytes raw: Raw data holding height, order, signature and hashes.
        """
        self.sec_mode = SPSESecModes.SCMP_AUTH_HASH_TREE
        self.height = 0
        self.order = []
        self.signature = []
        self.hashes = []
        super().__init__(raw)

    def _parse(self, raw):
        """
        Parse payload to extract values.

        :param bytes raw: raw payload.
        """
        data = Raw(raw, self.NAME)
        super()._parse(data)

        self.sec_mode = data.pop(SPSELengths.SECMODE)
        self.height = data.pop(SCMPAuthLengths.HEIGHT)
        self.order = data.pop(SCMPAuthLengths.ORDER)
        self.signature = data.pop(SCMPAuthLengths.SIGNATURE)
        self.hashes = data.pop(self.height_to_hashes_len(self.height))

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
        :raises: SPSEBaseError
        """
        error = cls.check_validity(height, order, signature, hashes)
        if error:
            raise error

        inst = cls()
        inst.height = height
        inst.order = order
        inst.signature = signature
        inst.hashes = hashes
        hdr_len = inst.bytes_to_hdr_len(SCMPAuthLengths.HASH_TREE_MIN_LENGTH +
                                        inst.height_to_hashes_len(height))
        inst._init_size(hdr_len)
        return inst

    def pack(self):
        """
        Pack extension into byte string

        :returns: packed extension.
        :rtype: bytes
        """
        packed = [struct.pack("!B", self.sec_mode),
                  struct.pack("!B", self.height),
                  self.order,
                  self.signature,
                  self.hashes]
        raw = b"".join(packed)
        self._check_len(raw)
        return raw

    @staticmethod
    def height_to_hashes_len(height):
        """
        Compute the byte length of the hashes, given the height of the tree.

        :param int height: Height of the hash tree.
        :returns: Byte length of the hashes.
        :rtype: int
        """
        return height * SCMPAuthLengths.HASH

    @staticmethod
    def check_validity(height, order, signature, hashes):
        """
        Check if parameters are valid

        :param int height: Height of the hash tree.
        :param bytes order: bit vector indicating left or right hash.
        :param bytes signature: Signature of the resulting hash.
        :param bytes hashes: Hashes needed to conduct the proof.
        :returns: An error if invalid parameters, None otherwise.
        :rtype: SPSEBaseError
        """

        if not 0 <= height <= MAX_HEIGHT:
            return SPSEBaseError("Invalid height %s. Max height %s" % (
                height, MAX_HEIGHT))
        if not len(order) == SCMPAuthLengths.ORDER:
            return SPSEBaseError("Invalid order length %s. Expected %s" % (
                len(order), SCMPAuthLengths.ORDER))
        if not len(signature) == SCMPAuthLengths.SIGNATURE:
            return SPSEBaseError("Invalid signature length %s. Expected %s" % (
                len(signature), SCMPAuthLengths.SIGNATURE))
        if not len(hashes) == SCMPAuthHashTreeExtn.height_to_hashes_len(height):
            return SPSEBaseError("Invalid order length %s. Expected %s" % (
                len(hashes), SCMPAuthHashTreeExtn.height_to_hashes_len(height)))
        return None

    def __str__(self):
        return ("%s(%sB):\n\tHeight: %s\n\tOrder: %s\n\t"
                "Signature: %s\n\tHashes: %s" % (
                 self.NAME, len(self), self.height, hex_str(self.order),
                 hex_str(self.signature), hex_str(self.hashes)))
