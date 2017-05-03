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
:mod:`extn` --- SCION Packet Security extension header
=================================================================
"""
# Stdlib
import struct

# SCION
from lib.packet.ext_hdr import EndToEndExtension
from lib.packet.spse.defines import (
    SPSEBaseError,
    SPSELengths,
    SPSESecModes
)
from lib.types import ExtEndToEndType
from lib.util import hex_str, Raw


class SCIONPacketSecurityExtn(EndToEndExtension):
    """
    Implementation of SCIONPacket security extension.

    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx |SecMode |       Metadata (var length)       |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                      Authenticator (var length)                       |
    +--------+--------+--------+--------+--------+--------+--------+--------+

    len(Metadata)      = 4 + 8i , where i in [0,1,...]
    len(Authenticator) = 8i     , where i in [1,2,...]
    """
    NAME = "SCIONPacketSecurityExtn"
    EXT_TYPE = ExtEndToEndType.SCION_PACKET_SECURITY

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param bytes raw: Raw data holding SecMode, Metadata and authenticator
        """
        self.sec_mode = 0
        self.metadata = []
        self.authenticator = []
        super().__init__(raw)

    def _parse(self, raw):
        """
        Parse payload to extract values.
        :param bytes raw: raw payload.
        """
        data = Raw(raw, self.NAME)
        super()._parse(data)

        self.sec_mode = data.pop(SPSELengths.SECMODE)
        self.metadata = data.pop(SPSELengths.META[self.sec_mode])
        self.authenticator = data.pop(SPSELengths.AUTH[self.sec_mode])

    @classmethod
    def from_values(cls, sec_mode, metadata, authenticator):  # pragma: no cover
        """
        Construct extension.

        :param int sec_mode: The SecMode of the extension.
        :param bytes metadata: The metadata of the extension.
        :param bytes authenticator: The authenticator of the extension.
        :returns: The created instance.
        :rtype: SCIONPacketSecurityExtn
        :raises: SPSEBaseError
        """
        error = cls.check_validity(sec_mode, metadata, authenticator)
        if error:
            raise error
        inst = cls()
        inst._init_size(inst.bytes_to_hdr_len(SPSELengths.TOTAL[sec_mode]))
        inst.sec_mode = sec_mode
        inst.metadata = metadata
        inst.authenticator = authenticator
        return inst

    def pack(self):
        """
        Pack extension into byte string.

        :returns: packed extension.
        :rtype: bytes
        """
        packed = [struct.pack("!B", self.sec_mode), self.metadata,
                  self.authenticator]
        raw = b"".join(packed)
        self._check_len(raw)
        return raw

    @staticmethod
    def check_validity(sec_mode, metadata, authenticator):
        """
        Check if parameters are valid.

        :param int sec_mode: The SecMode of the extension.
        :param bytes metadata: The metadata of the extension.
        :param bytes authenticator: The authenticator of the extension.
        :returns: An error if invalid parameters, None otherwise.
        :rtype: SPSEBaseError
        """

        if sec_mode not in SPSESecModes.SUPPORTED_SECMODES:
            return SPSEBaseError("Invalid SecMode %s" % sec_mode)
        if len(metadata) != SPSELengths.META[sec_mode]:
            return SPSEBaseError("Invalid metadata length %s. Expected %s" % (
                sec_mode, SPSELengths.META[sec_mode]))
        if len(authenticator) != SPSELengths.AUTH[sec_mode]:
            return SPSEBaseError("Invalid auth length %s. Expected %s" % (
                sec_mode, SPSELengths.AUTH[sec_mode]))
        return None

    def __str__(self):
        return "%s(%sB):\n\tMeta: %s\n\tAuth: %s" % (
            self.NAME, len(self), hex_str(self.metadata),
            hex_str(self.authenticator))
