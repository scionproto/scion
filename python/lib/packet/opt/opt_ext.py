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
from lib.crypto.symcrypto import mac
from lib.packet.opt.defines import (
    OPTLengths,
    OPTValidationError, OPTMode)
from lib.packet.opt.base_ext import SCIONOriginPathTraceBaseExtn
from lib.util import hex_str, Raw


class SCIONOriginValidationPathTraceExtn(SCIONOriginPathTraceBaseExtn):
    """
    Implementation of SCION Origin Validation and Path Trace extension.

    OPT extension Header

    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx |  Mode  |            Timestamp              |
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
    +--------+--------+----i----+--------+--------+--------+--------+-------+
    |                                  OV_i ...                             |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                               ...OV_i  (var length)                   |
    +--------+--------+--------+--------+--------+--------+--------+--------+

    """
    NAME = "OriginValidationPathTrace"

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param bytes raw: Raw data holding DataHash, SessionID and PVF
        """
        self.PVF = bytes(OPTLengths.PVF)
        self.OVs = []
        super().__init__(raw)

    def _parse(self, raw):
        """
        Parse payload to extract values.
        :param bytes raw: raw payload.
        """
        data = Raw(raw, self.NAME)
        super()._parse(data)

        self.mode = bytes([data.pop(OPTLengths.MODE)])
        self.timestamp = data.pop(OPTLengths.TIMESTAMP)
        self.datahash = data.pop(OPTLengths.DATAHASH)
        self.sessionID = data.pop(OPTLengths.SESSIONID)
        self.PVF = data.pop(OPTLengths.PVF)
        all_ovs = data.pop()
        self.OVs = []
        if len(all_ovs) % 16 == 0:  # check we got valid OVs
            self.ov_count = len(all_ovs)//16
            for ov_index in range(len(all_ovs)):
                self.OVs.append(bytes(all_ovs[ov_index*OPTLengths.OVs:(ov_index+1)*OPTLengths.OVs]))

    @classmethod
    def from_values(cls, mode, timestamp, datahash, sessionID, PVF, OVs):  # pragma: no cover
        """
        Construct extension.

        :param bytes mode: The mode of the extension
        :param bytes timestamp: The timestamp when the extension was created
        :param bytes datahash: The hash of the payload
        :param bytes sessionID: The session ID of the extension.
        :param bytes PVF: The Path Verification Field for the extension
        :returns: The created instance.
        :rtype: OriginValidationPathTrace
        :raises: None
        """
        inst = cls()
        inst._init_size(inst.bytes_to_hdr_len(OPTLengths.TOTAL[OPTMode.OPT]+16*len(OVs))-1)
        inst.mode = mode
        inst.timestamp = timestamp
        inst.datahash = datahash
        inst.sessionID = sessionID
        inst.PVF = PVF
        inst.OVs = OVs
        return inst

    def pack(self):
        """
        Pack extension into byte string.

        :returns: packed extension.
        :rtype: bytes
        """
        packed = [self.mode, self.timestamp, self.datahash, self.sessionID,
                  self.PVF, b"".join(self.OVs)]
        raw = b"".join(packed)
        self._check_len(raw)
        return raw

    def init_pvf(self, key):
        self.PVF = mac(key, self.datahash)

    def create_ovs_from_path(self, key_list):
        ov_list = []
        for key in key_list:
            ov_list.append(mac(key.drkey, self.datahash))
        return ov_list

    @classmethod
    def check_validity(cls, datahash, sessionID, PVF, OVs):
        """
        Check if parameters are valid.

        :param bytes datahash: The hash of the payload
        :param bytes sessionID: The session ID of the extension.
        :param bytes PVF: The Path Verification Field for the extension
        :param bytes OVs: The Origin Validation Field for the extension
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
        if len(OVs) % OPTLengths.OVs != 0:
            raise OPTValidationError("Invalid OVs length %sB. Expected a multiple of %sB" % (
                len(OVs), OPTLengths.OVs))

    def __str__(self):
        return "%s(%sB):\n\tDatahash: %s\n\tSessionID: %s\n\tPVF: %s\n\tOVs: %s" % (
            self.NAME, len(self), hex_str(self.datahash),
            hex_str(self.sessionID), hex_str(self.PVF), hex_str(b"".join(self.OVs)))
