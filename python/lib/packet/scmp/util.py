# Copyright 2016 ETH Zurich
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
:mod:`util` --- SCMP utility functions.
=======================================
"""
# SCION
from lib.packet.scmp.types import (
    SCMPClass,
    SCMPCmnHdrClass,
    SCMPGeneralClass,
    SCMPIncParts,
    SCMPInfoType,
    SCMPPathClass,
    SCMPRoutingClass,
    SCMPExtClass,
)

_TYPE_MAP = {
    SCMPClass.GENERAL: SCMPGeneralClass,
    SCMPClass.ROUTING: SCMPRoutingClass,
    SCMPClass.CMNHDR: SCMPCmnHdrClass,
    SCMPClass.PATH: SCMPPathClass,
    SCMPClass.EXT: SCMPExtClass,
}


def scmp_type_name(class_, type_):  # pragma: no cover
    type_cls = _TYPE_MAP.get(class_)
    if not type_cls:
        return "UNKNOWN"
    return type_cls.to_str(type_)


INC_BASIC = [SCMPIncParts.CMN, SCMPIncParts.ADDRS, SCMPIncParts.L4]
INC_BASIC_PATH = INC_BASIC + [SCMPIncParts.PATH]
INC_BASIC_EXTS = INC_BASIC + [SCMPIncParts.EXTS]
INC_ALL = [SCMPIncParts.CMN, SCMPIncParts.ADDRS, SCMPIncParts.PATH,
           SCMPIncParts.EXTS, SCMPIncParts.L4]


def scmp_get_inc_parts(class_, type_):  # pragma: no cover
    if class_ == SCMPClass.GENERAL:
        if type_ == SCMPGeneralClass.UNSPECIFIED:
            return INC_ALL
        return None
    if class_ in (SCMPClass.ROUTING, SCMPClass.CMNHDR):
        return INC_BASIC
    if class_ == SCMPClass.PATH:
        if type_ == SCMPPathClass.PATH_REQUIRED:
            return INC_BASIC
        return INC_BASIC_PATH
    if class_ == SCMPClass.EXT:
        return INC_BASIC_EXTS


def scmp_get_info_type(class_, type_):  # pragma: no cover
    if class_ == SCMPClass.GENERAL:
        if type_ == SCMPGeneralClass.UNSPECIFIED:
            return SCMPInfoType.STRING
        return SCMPInfoType.ECHO
    elif class_ == SCMPClass.ROUTING:
        if type_ == SCMPRoutingClass.OVERSIZE_PKT:
            return SCMPInfoType.PKT_SIZE
    elif class_ == SCMPClass.CMNHDR:
        if type_ == SCMPCmnHdrClass.BAD_PKT_LEN:
            return SCMPInfoType.PKT_SIZE
    elif class_ == SCMPClass.PATH:
        if type_ == SCMPPathClass.PATH_REQUIRED:
            return None
        elif type_ == SCMPPathClass.REVOKED_IF:
            return SCMPInfoType.REVOCATION
        return SCMPInfoType.PATH_OFFSETS
    elif class_ == SCMPClass.EXT:
        return SCMPInfoType.EXT_IDX
    return None
