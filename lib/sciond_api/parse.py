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
:mod:`parse` --- Parse SCIOND messages
========================================
"""
# SCION
import proto.sciond_capnp as P
from lib.errors import SCIONParseError
from lib.sciond_api.path_req import SCIONDPathReply, SCIONDPathRequest


def parse_sciond_msg(raw):  # pragma: no cover
    wrapper = P.SCIONDMsg.from_bytes_packed(raw).as_builder()
    type_ = wrapper.which()
    for cls_ in (SCIONDPathReply, SCIONDPathRequest):
        if cls_.MSG_TYPE == type_:
            return cls_(getattr(wrapper, type_))
    raise SCIONParseError("Unsupported SCIOND message type: %s" % type_)
