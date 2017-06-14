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
:mod:`extn` --- SCION Origin validation and Path Trace extension
=================================================================
"""
# Stdlib

# SCION
from lib.packet.ext_hdr import EndToEndExtension
from lib.packet.opt.defines import (
    OPTLengths,
    OPTValidationError)
from lib.types import ExtEndToEndType
from lib.util import hex_str, Raw


class SCIONOriginPathTraceBaseExtn(EndToEndExtension):
    """
    Base class of SCION Packet Security extension.
    """
    EXT_TYPE = ExtEndToEndType.OPT

    def __init__(self, raw=None):
        super().__init__(raw)


class SCIONOriginPathTraceExtn(SCIONOriginPathTraceBaseExtn):
    """
    Implementation of SCION Origin Validation and Path Trace extension.

    OPT extension Header

    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx |                    padding                 |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                               DataHash...                             |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                            ...DataHash                                |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                               Session ID...                           |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                            ...Session ID                              |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                                  PVF...                               |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                               ...PVF                                  |
    +--------+--------+--------+--------+--------+--------+--------+--------+

    """
    NAME = "SCIONOriginPathTraceExtn"

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param bytes raw: Raw data holding DataHash, SessionID and PVF
        """
        self.padding = b" "*5
        self.datahash = b" "*16
        self.sessionID = b" "*16
        self.PVF = b" "*16
        super().__init__(raw)

    def _parse(self, raw):
        """
        Parse payload to extract values.
        :param bytes raw: raw payload.
        """
        data = Raw(raw, self.NAME)
        super()._parse(data)

        self.datahash = data.pop(OPTLengths.DATAHASH)
        self.sessionID = data.pop(OPTLengths.SESSIONID)
        self.PVF = data.pop(OPTLengths.PVF)

    @classmethod
    def from_values(cls, datahash, sessionID, PVF):  # pragma: no cover
        """
        Construct extension.

        :param bytes datahash: The hash of the payload
        :param bytes sessionID: The session ID of the extension.
        :param bytes PVF: The Path Verification Field for the extension
        :returns: The created instance.
        :rtype: SCIONOriginPathTraceExtn
        :raises: None
        """
        inst = cls()
        inst._init_size(inst.bytes_to_hdr_len(OPTLengths.TOTAL))
        inst.datahash = datahash
        inst.sessionID = sessionID
        inst.PVF = PVF
        return inst

    def pack(self):
        """
        Pack extension into byte string.

        :returns: packed extension.
        :rtype: bytes
        """
        packed = [self.padding, self.datahash, self.sessionID,
                  self.PVF]
        raw = b"".join(packed)
        self._check_len(raw)
        return raw

    @classmethod
    def check_validity(cls, datahash, sessionID, PVF):
        """
        Check if parameters are valid.

        :param bytes datahash: The hash of the payload
        :param bytes sessionID: The session ID of the extension.
        :param bytes PVF: The Path Verification Field for the extension
        :raises: OPTValidationError
        """

        if len(datahash) != OPTLengths.DATAHASH:
            raise OPTValidationError("Invalid datahash length %sB. Expected %sB" % (
                len(datahash), OPTLengths.DATAHASH))
        if len(sessionID) != OPTLengths.SESSIONID:
            raise OPTValidationError("Invalid sessionID length %sB. Expected %sB" % (
                len(sessionID), OPTLengths.SESSIONID))
        if len(PVF) != OPTLengths.PVF:
            raise OPTValidationError("Invalid PVF length %sB. Expected %sB" % (
                len(PVF), OPTLengths.PVF))

    def __str__(self):
        return "%s(%sB):\n\tDatahash: %s\n\tSessionID: %s\n\tPVF: %s" % (
            self.NAME, len(self), hex_str(self.datahash),
            hex_str(self.sessionID), hex_str(self.PVF))
