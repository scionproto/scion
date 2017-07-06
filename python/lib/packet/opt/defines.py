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
:mod:`defines` --- Parse SCIONOriginPathTrace extension
========================================
"""
# Stdlib

# SCION
from lib.errors import SCIONBaseError


class OPTBaseError(SCIONBaseError):
    """Root OPT Error exception. All other OPT errors derive from this."""


class OPTValidationError(OPTBaseError):
    """Validation error"""


class OPTMode:
    """
    SCION Origin Validation and Path Trace extension modes
    """
    OPT = 0
    PATH_TRACE_ONLY = 1
    ORIGIN_VALIDATION_ONLY = 2


class OPTLengths:
    """
    SCIONOriginPathTrace extension constant lengths.
    """
    MODE = 1
    TIMESTAMP = 4
    DATAHASH = 16
    SESSIONID = 16
    PVF = 16
    OVs = 16

    TOTAL = {  # OVs are not accounted for
        OPTMode.OPT: MODE + TIMESTAMP + DATAHASH + SESSIONID + PVF,
        OPTMode.PATH_TRACE_ONLY: MODE + TIMESTAMP + DATAHASH + SESSIONID + PVF,
        OPTMode.ORIGIN_VALIDATION_ONLY: MODE + TIMESTAMP + DATAHASH + SESSIONID
    }
