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
:mod:`base` --- Base class for path mgmt packets
================================================
"""
# External
import capnp  # noqa

# SCION
import proto.path_mgmt_capnp as P
from lib.packet.packet_base import CerealBox
from lib.types import PathMgmtType
from lib.packet.path_mgmt.ifstate import IFStatePayload, IFStateRequest
from lib.packet.path_mgmt.rev_info import SignedRevInfo
from lib.packet.path_mgmt.seg_recs import PathRecordsReg, PathRecordsSync
from lib.packet.path_mgmt.seg_req import PathSegmentReq, PathSegmentReply


class PathMgmt(CerealBox):  # pragma: no cover
    NAME = "PathMgmt"
    P_CLS = P.PathMgmt
    CLASS_FIELD_MAP = {
        PathSegmentReq: PathMgmtType.REQUEST,
        PathSegmentReply: PathMgmtType.REPLY,
        PathRecordsReg: PathMgmtType.REG,
        PathRecordsSync: PathMgmtType.SYNC,
        SignedRevInfo: PathMgmtType.REVOCATION,
        IFStateRequest: PathMgmtType.IFSTATE_REQ,
        IFStatePayload: PathMgmtType.IFSTATE_INFOS,
    }
