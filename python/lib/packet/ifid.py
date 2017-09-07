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
:mod:`ifid` --- Interface ID payload
====================================
"""
# External
import capnp  # noqa

# SCION
import proto.ifid_capnp as P
from lib.packet.packet_base import Cerealizable


class IFIDPayload(Cerealizable):  # pragma: no cover
    """
    IFID packet.
    """
    NAME = "IFIDPayload"
    P_CLS = P.IFID

    @classmethod
    def from_values(cls, orig_if):  # pragma: no cover
        return cls(cls.P_CLS.new_message(origIF=orig_if))


def parse_ifid_payload(p):  # pragma: no cover
    return IFIDPayload(p)
