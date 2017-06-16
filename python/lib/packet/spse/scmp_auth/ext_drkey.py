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
from lib.types import TypeBase
from lib.util import hex_str, Raw


class SCMPAuthDRKeyLengths:
    """
    Constant lengths.
    """
    DIRECTION = 1
    MAC = 16
    PADDING = 3
    DRKEY_TOTAL_LENGTH = SPSELengths.SECMODE + DIRECTION + PADDING + MAC


class SCMPAuthDRKeyDirections(TypeBase):
    """
    Direction defines.
    """
    AS_TO_AS = 0  # Authenticated with S -> D
    AS_TO_HOST = 1  # Authenticated with S -> D:HD
    HOST_TO_HOST = 2  # Authenticated with S:HS -> D:HD
    HOST_TO_AS = 3  # Authenticated with D -> S:HS
    AS_TO_AS_REVERSED = 4  # Authenticated with D -> S
    HOST_TO_HOST_REVERSED = 5  # Authenticated with D:HD -> S:HS

    @staticmethod
    def is_valid_direction(direction):
        """
        Check if a valid direction has been provided.

        :param int direction: Direction value.
        :returns: If the direction is valid.
        :rtype: bool
        """
        return 0 <= direction <= 5


class SCMPAuthDRKeyExtn(SCIONPacketSecurityBaseExtn):
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

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param bytes raw: Raw data holding direction and mac.
        """
        self.direction = 0
        self.mac = b""
        super().__init__(raw)

    def _parse(self, raw):
        """
        Parse payload to extract values.

        :param bytes raw: raw payload.
        """
        data = Raw(raw, self.NAME)
        super()._parse(data)

        self.sec_mode = data.pop(SPSELengths.SECMODE)
        self.direction = data.pop(SCMPAuthDRKeyLengths.DIRECTION)
        data.pop(SCMPAuthDRKeyLengths.PADDING)
        self.mac = data.pop(SCMPAuthDRKeyLengths.MAC)

    @classmethod
    def from_values(cls, direction, mac=None):  # pragma: no cover
        """
        Construct extension.

        :param int direction: Indicates which key was used for authentication.
        :param bytes mac: The mac of the extension. If None set to all zeros.
        :returns: The created instance.
        :rtype: SCMPAuthDRKeyExtn
        :raises: SPSEValidationError
        """
        cls.check_validity(direction, mac)
        inst = cls()
        inst.sec_mode = SPSESecModes.SCMP_AUTH_DRKEY
        inst._init_size(inst.bytes_to_hdr_len(SCMPAuthDRKeyLengths.DRKEY_TOTAL_LENGTH)-1)
        inst.direction = direction
        inst.mac = mac or bytes(SCMPAuthDRKeyLengths.MAC)
        return inst

    def pack(self):
        """
        Pack extension into byte string

        :returns: packed extension.
        :rtype: bytes
        """
        packed = [struct.pack("!B", self.sec_mode),
                  struct.pack("!B", self.direction),
                  bytes(SCMPAuthDRKeyLengths.PADDING),
                  self.mac]
        raw = b"".join(packed)
        self._check_len(raw)
        return raw

    @classmethod
    def check_validity(cls, direction, mac):
        """
        Check if parameters are valid.

        :param int direction: Indicates which key was used for authentication.
        :param bytes mac: The mac of the extension.
        :raises: SPSEValidationError
        """

        if not SCMPAuthDRKeyDirections.is_valid_direction(direction):
            raise SPSEValidationError("Invalid direction %s" % direction)
        if mac and len(mac) != SCMPAuthDRKeyLengths.MAC:
            raise SPSEValidationError("Invalid mac length %sB. Expected %sB" % (
                len(mac), SCMPAuthDRKeyLengths.MAC))

    def __str__(self):
        return "%s(%sB): Direction: %s MAC: %s" % (
            self.NAME, len(self), SCMPAuthDRKeyDirections.to_str(self.direction), hex_str(self.mac))
