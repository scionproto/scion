# Copyright 2015 ETH Zurich
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
:mod:`security` --- Security extension header
=================================================================
"""
# Stdlib
import struct

# SCION
from lib.errors import SCIONBaseError
from lib.packet.ext_hdr import EndToEndExtension
from lib.util import Raw
from lib.types import ExtEndToEndType


class SecurityExt(EndToEndExtension):
    """
    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx |SecMode |       Metadata (var length)       |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                      Authenticator (var length)                       |
    +--------+--------+--------+--------+--------+--------+--------+--------+

    len(Metadata)      = 4 + 8i , where i in [0,1,...]
    len(Authenticator) = 8i     , where i in [1,2,...]
    """
    NAME = "SecurityExt"
    EXT_TYPE = ExtEndToEndType.SECURITY

    def __init__(self, raw=None):  # pragma: no cover
        self.sec_mode = 0
        self.metadata = []
        self.authenticator = []
        super().__init__(raw)

    def _parse(self, raw):
        """
        Parse payload to extract hop informations.
        """
        self.sec_mode = raw[0]

        data = Raw(raw, self.NAME)
        super()._parse(data)
        # Drop hops no and padding from the first row.
        data.pop(Lengths.SECMODE)

        self.metadata = data.pop(META_LENGTH[self.sec_mode])

        if self.sec_mode == SecModes.SCMP_AUTH_HASH_TREE:
            height = self.metadata[Lengths.TIMESTAMP]
            self.authenticator = data.pop(SCMPAuthLengths.SIGNATURE + height * SCMPAuthLengths.HASH)
        else:
            self.authenticator = data.pop(AUTH_LENGTH[self.sec_mode])

    @classmethod
    def from_values(cls, sec_mode, metadata, authenticator, height=None):  # pragma: no cover
        """
        Construct extension.
        """
        inst = SecurityExt()
        if sec_mode == SecModes.SCMP_AUTH_HASH_TREE:
            if not height:
                raise SCIONBaseError("SecurityExt.from_values: Attempted to create SCMPAuthHashTree "
                                     "without providing height")
            inst._init_size(SCMPAuthLengths.HEIGHT + SCMPAuthLengths.ORDER + SCMPAuthLengths.SIGNATURE +
                            height * SCMPAuthLengths.HASH)
            inst.height = height
        else:
            inst._init_size(TotalLength[sec_mode])

        inst.sec_mode = sec_mode
        inst.metadata = metadata
        inst.authenticator = authenticator

        return inst

    def pack(self):
        packed = [struct.pack("!B", self.sec_mode), self.metadata, self.authenticator]
        raw = b"".join(packed)
        self._check_len(raw)
        return raw

    def __str__(self):
        return "%s(%sB):\n\tMeta: %s\n\tAuth: %s" % (self.NAME, len(self), self.metadata, self.authenticator)


class Lengths:
    TIMESTAMP = 4
    SECMODE = 1


class SecModes:
    AES_CMAC = 0
    HMAC_SHA256 = 1
    ED25519 = 2
    GCM_AES128 = 3
    SCMP_AUTH_DRKEY = 4
    SCMP_AUTH_HASHED_DRKEY = 5
    SCMP_AUTH_HASH_TREE = 6


class SCMPAuthLengths:
    HASH = 16
    HEIGHT = 1
    ORDER = 7
    SIGNATURE = 64
    MAC = 16

META_LENGTH = {
    SecModes.AES_CMAC: Lengths.TIMESTAMP,
    SecModes.HMAC_SHA256: Lengths.TIMESTAMP,
    SecModes.ED25519: Lengths.TIMESTAMP,
    SecModes.GCM_AES128: Lengths.TIMESTAMP,
    SecModes.SCMP_AUTH_DRKEY: Lengths.TIMESTAMP,
    SecModes.SCMP_AUTH_HASHED_DRKEY: Lengths.TIMESTAMP + SCMPAuthLengths.HASH,
    SecModes.SCMP_AUTH_HASH_TREE: Lengths.TIMESTAMP + SCMPAuthLengths.HEIGHT + SCMPAuthLengths.ORDER,
}

AUTH_LENGTH = {
    SecModes.AES_CMAC: 16,
    SecModes.HMAC_SHA256: 32,
    SecModes.ED25519: 64,
    SecModes.GCM_AES128: 16,
    SecModes.SCMP_AUTH_DRKEY: SCMPAuthLengths.MAC,
    SecModes.SCMP_AUTH_HASHED_DRKEY: SCMPAuthLengths.MAC,
}

TotalLength = {
    SecModes.AES_CMAC: Lengths.SECMODE + META_LENGTH[SecModes.AES_CMAC] + AUTH_LENGTH[SecModes.AES_CMAC],
    SecModes.HMAC_SHA256: Lengths.SECMODE + META_LENGTH[SecModes.HMAC_SHA256] + AUTH_LENGTH[SecModes.HMAC_SHA256],
    SecModes.ED25519: Lengths.SECMODE + META_LENGTH[SecModes.ED25519] + AUTH_LENGTH[SecModes.ED25519],
    SecModes.GCM_AES128: Lengths.SECMODE + META_LENGTH[SecModes.GCM_AES128] + AUTH_LENGTH[SecModes.GCM_AES128],
    SecModes.SCMP_AUTH_DRKEY: Lengths.SECMODE + META_LENGTH[SecModes.SCMP_AUTH_DRKEY] +
                              AUTH_LENGTH[SecModes.SCMP_AUTH_DRKEY],
    SecModes.SCMP_AUTH_HASHED_DRKEY: Lengths.SECMODE + META_LENGTH[SecModes.SCMP_AUTH_HASHED_DRKEY] +
                                     AUTH_LENGTH[SecModes.SCMP_AUTH_HASHED_DRKEY],
}