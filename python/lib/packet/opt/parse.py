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
:mod:`parse` --- Parse SCIONOriginPathTrace extension
========================================
"""

# SCION
from lib.packet.opt.base_ext import SCIONOriginPathTraceBaseExtn
from lib.packet.opt.defines import OPTMode


def parse_opt(raw):  # pragma: no cover
    """
    Parses the SCIONOriginPathTrace extension depending on the OPT mode
    """
    mode = raw[0]
    if mode in OPTMode.OPT:
        return SCIONOriginValidationPathTraceExtn(raw)
    if mode in OPTMode.PATH_TRACE_ONLY:
        return SCIONPathTraceExtn(raw)
    if mode in OPTMode.ORIGIN_VALIDATION_ONLY:
        return SCIONOriginValidationExtn(raw)
    raise SCIONParseError("Unable to parse OPT. Invalid sec mode %s" % mode)
