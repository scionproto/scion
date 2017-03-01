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
from lib.packet.packet_base import Cerealizable
from lib.types import SCIONDMsgType as SMT


class SCIONDMsgBase(Cerealizable):  # pragma: no cover
    # Needs to be set to the proper message type by each subclass.
    MSG_TYPE = SMT.UNSET
