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
:mod:`seg` --- Base class for Hidden path packets
==================================================
"""

# SCION
from lib.packet.path_mgmt.seg_req import PathSegmentReq, PathSegmentReply
from lib.packet.path_mgmt.seg_recs import PathSegmentRecords


class HPSegReg(PathSegmentRecords):
    NAME = "HPSegReg"


class HPSegReply(PathSegmentReply):
    NAME = "HPSegReply"


class HPSegReq(PathSegmentReq):
    NAME = "HPSegReq"
