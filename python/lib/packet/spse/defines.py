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
:mod:`defines` --- SCION Packet Security extension definitions
=================================================================
"""
# Stdlib

# SCION
from lib.errors import SCIONBaseError
from lib.types import TypeBase


class SPSEBaseError(SCIONBaseError):
    """Root SPSE Error exception. All other SPSE errors derive from this."""


class SPSEValidationError(SPSEBaseError):
    """Validation error"""


class SPSESecModes(TypeBase):
    """
    Available SecModes
    """
    AES_CMAC = 0
    HMAC_SHA256 = 1
    ED25519 = 2
    GCM_AES128 = 3
    SCMP_AUTH_DRKEY = 4
    SCMP_AUTH_HASH_TREE = 5


class SPSELengths:
    """
    SCIONPacketSecurity extension constant lengths.
    """
    TIMESTAMP = 4
    SECMODE = 1

    META = {
        SPSESecModes.AES_CMAC: TIMESTAMP,
        SPSESecModes.HMAC_SHA256: TIMESTAMP,
        SPSESecModes.ED25519: TIMESTAMP,
        SPSESecModes.GCM_AES128: TIMESTAMP,
    }

    AUTH = {
        SPSESecModes.AES_CMAC: 16,
        SPSESecModes.HMAC_SHA256: 32,
        SPSESecModes.ED25519: 64,
        SPSESecModes.GCM_AES128: 16,
    }

    TOTAL = {
        SPSESecModes.AES_CMAC:
            SECMODE + META[SPSESecModes.AES_CMAC] + AUTH[SPSESecModes.AES_CMAC],
        SPSESecModes.HMAC_SHA256:
            SECMODE + META[SPSESecModes.HMAC_SHA256] + AUTH[SPSESecModes.HMAC_SHA256],
        SPSESecModes.ED25519:
            SECMODE + META[SPSESecModes.ED25519] + AUTH[SPSESecModes.ED25519],
        SPSESecModes.GCM_AES128:
            SECMODE + META[SPSESecModes.GCM_AES128] + AUTH[SPSESecModes.GCM_AES128],
    }
