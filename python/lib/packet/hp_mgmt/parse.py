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
import logging

# SCION
from lib.errors import SCIONParseError
from lib.packet.hp_mgmt.cfg_recs import (
    HiddenPathConfigRecordsReg,
    HiddenPathConfigRecordsReply,
)
from lib.packet.hp_mgmt.cfg_req import HiddenPathConfigReq
from lib.packet.hp_mgmt.seg_recs import (
    HiddenPathRecordsReg,
    HiddenPathRecordsReply,
)
from lib.packet.hp_mgmt.seg_req import HiddenPathSegmentReq


def parse_hp_mgmt_payload(wrapper):  # pragma: no cover
    type_ = wrapper.which()
    timestamp = wrapper.timestamp
    signature = wrapper.signature
    for cls_ in (
        HiddenPathSegmentReq, HiddenPathRecordsReply, HiddenPathRecordsReg,
        HiddenPathConfigReq, HiddenPathConfigRecordsReply, HiddenPathConfigRecordsReg,
    ):
        if cls_.PAYLOAD_TYPE == type_:
            logging.debug(type_)
            logging.debug(timestamp)
            logging.debug(signature)
            inst = cls_(getattr(wrapper, type_), timestamp)
            inst.signature = signature
            return inst
    raise SCIONParseError("Unsupported hidden path management type: %s" % type_)
