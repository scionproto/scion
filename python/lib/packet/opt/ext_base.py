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
    OPTLengths
)
from lib.types import ExtEndToEndType


class SCIONOriginPathTraceBaseExtn(EndToEndExtension):
    """
    Implementation of SCION Origin Validation and Path Trace Base extension.

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
    """
    EXT_TYPE = ExtEndToEndType.OPT
    NAME = "SCIONOriginPathTraceExtn"

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param bytes raw: Raw data holding DataHash, SessionID and PVF
        """
        self.mode = bytes(OPTLengths.MODE)
        self.timestamp = bytes(OPTLengths.TIMESTAMP)
        self.datahash = bytes(OPTLengths.DATAHASH)
        self.sessionID = bytes(OPTLengths.SESSIONID)
        super().__init__(raw)
