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
from lib.packet.packet_base import SCIONPayloadBaseProto
from lib.types import PayloadClass


class PathMgmtPayloadBase(SCIONPayloadBaseProto):  # pragma: no cover
    PAYLOAD_CLASS = PayloadClass.PATH

    def _pack_full(self, p):
        wrapper = P.PathMgmt.new_message(**{self.PAYLOAD_TYPE: p})
        return super()._pack_full(wrapper)
