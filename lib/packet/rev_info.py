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
:mod:`rev_info` --- Revocation info packets
============================================

Contains the packet format used for revocations.
"""
# Stdlib
import struct

# SCION
from lib.types import PathMgmtType as PMT
from lib.packet.packet_base import PathMgmtPayloadBase
from lib.util import Raw


class RevocationInfo(PathMgmtPayloadBase):
    """
    Class containing revocation information, i.e., the revocation token.
    """
    NAME = "RevocationInfo"
    PAYLOAD_TYPE = PMT.REVOCATION
    LEN = 32

    def __init__(self, raw=None):  # pragma: no cover
        super().__init__()
        self.rev_token = b""
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.rev_token = struct.unpack("!32s", data.pop(self.LEN))[0]

    @classmethod
    def from_values(cls, rev_token):
        """
        Returns a RevocationInfo object with the specified values.

        :param bytes rev_token: revocation token of interface
        """
        inst = cls()
        inst.rev_token = rev_token
        return inst

    def pack(self):
        return struct.pack("!32s", self.rev_token)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        return "%s(%sB): %s" % (self.NAME, len(self), self.rev_token)
