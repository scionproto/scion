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
    SPSEValidationError,
    SPSELengths,
    SPSESecModes
)
from lib.types import ExtEndToEndType
from lib.util import hex_str, Raw


class SCIONPacketSecurityBaseExtn(EndToEndExtension):
    """
    Base class of SCION Packet Security extension.
    """
    EXT_TYPE = ExtEndToEndType.SPSE

    def __init__(self, raw=None):
        self.sec_mode = None
        super().__init__(raw)


class SCIONPacketSecurityExtn(SCIONPacketSecurityBaseExtn):
    """
    Implementation of SCIONPacket Security extension.

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

    # SecModes supported by SCIONPacketSecurityExtn
    SUPPORTED_SECMODES = {
        SPSESecModes.AES_CMAC,
        SPSESecModes.HMAC_SHA256,
        SPSESecModes.ED25519,
        SPSESecModes.GCM_AES128,
    }

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param bytes raw: Raw data holding SecMode, Metadata and authenticator
        """
        self.metadata = b""
        self.authenticator = b""
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
        :raises: SPSEValidationError
        """
        cls.check_validity(sec_mode, metadata, authenticator)
        inst = cls()
        inst._init_size(inst.bytes_to_hdr_len(SPSELengths.TOTAL[sec_mode])-1)
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

    @classmethod
    def check_validity(cls, sec_mode, metadata, authenticator):
        """
        Check if parameters are valid.

        :param int sec_mode: The SecMode of the extension.
        :param bytes metadata: The metadata of the extension.
        :param bytes authenticator: The authenticator of the extension.
        :raises: SPSEValidationError
        """

        if sec_mode not in cls.SUPPORTED_SECMODES:
            raise SPSEValidationError("Invalid SecMode %s" % sec_mode)
        if len(metadata) != SPSELengths.META[sec_mode]:
            raise SPSEValidationError("Invalid metadata length %sB. Expected %sB" % (
                len(metadata), SPSELengths.META[sec_mode]))
        if len(authenticator) != SPSELengths.AUTH[sec_mode]:
            raise SPSEValidationError("Invalid auth length %sB. Expected %sB" % (
                len(authenticator), SPSELengths.AUTH[sec_mode]))

    def __str__(self):
        return "%s(%sB):\n\tMeta: %s\n\tAuth: %s" % (
            self.NAME, len(self), hex_str(self.metadata),
            hex_str(self.authenticator))
