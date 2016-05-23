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
:mod:`parse` --- Parse path mgmt packets
========================================
"""

# SCION
from lib.errors import SCIONParseError
from lib.packet.path_mgmt.ifstate import IFStatePayload, IFStateRequest
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.path_mgmt.seg_recs import (
    PathRecordsReg,
    PathRecordsReply,
    PathRecordsSync,
)
from lib.packet.path_mgmt.seg_req import PathSegmentReq
from lib.types import PathMgmtType as PMT


_TYPE_MAP = {
    PMT.REQUEST: PathSegmentReq,
    PMT.REPLY: PathRecordsReply,
    PMT.REG: PathRecordsReg,
    PMT.SYNC: PathRecordsSync,
    PMT.REVOCATION: RevocationInfo,
    PMT.IFSTATE_INFO: IFStatePayload,
    PMT.IFSTATE_REQ: IFStateRequest,
}


def parse_pathmgmt_payload(type_, data):
    if type_ not in _TYPE_MAP:
        raise SCIONParseError("Unsupported path management type: %s", type_)
    handler = _TYPE_MAP[type_]
    return handler.from_raw(data.pop())
