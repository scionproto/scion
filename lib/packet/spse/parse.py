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
:mod:`parse` --- Parse SCIONPacketSecurity extension
========================================
"""

# SCION
from lib.errors import SCIONParseError
from lib.packet.spse.defines import SPSESecModes
from lib.packet.spse.ext import SCIONPacketSecurityExtn
from lib.packet.spse.scmp_auth.ext_drkey import SCMPAuthDRKeyExtn
from lib.packet.spse.scmp_auth.ext_hashtree import SCMPAuthHashTreeExtn


def parse_spse(raw):  # pragma: no cover
    """
    Parses the SCIONPacketSecurity extension according to the security mode.
    """
    sec_mode = raw[0]
    if sec_mode in SCIONPacketSecurityExtn.SUPPORTED_SECMODES:
        return SCIONPacketSecurityExtn(raw)
    if sec_mode == SPSESecModes.SCMP_AUTH_DRKEY:
        return SCMPAuthDRKeyExtn(raw)
    if sec_mode == SPSESecModes.SCMP_AUTH_HASH_TREE:
        return SCMPAuthHashTreeExtn(raw)
    raise SCIONParseError("Unable to parse SPSE. Invalid sec mode %s" % sec_mode)
