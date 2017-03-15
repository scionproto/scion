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
:mod:`base` --- Base class for SCIOND messages
==============================================
"""
# SCION
import proto.sciond_capnp as P
from lib.packet.packet_base import Cerealizable


class SCIONDMsgBase(Cerealizable):  # pragma: no cover
    """
    Base class for SCIOND API messages.

    Subclasses need to set cls.MSG_TYPE to an appropriate value.
    """
    def __init__(self, p, id):
        super().__init__(p)
        self.id = id

    def pack_full(self):
        assert not self._packed, "May only be packed once"
        self._packed = True
        return self._pack_full(self.p)

    def _pack_full(self, p):
        wrapper = P.SCIONDMsg.new_message(id=self.id, **{self.MSG_TYPE: p})
        return wrapper.to_bytes_packed()
