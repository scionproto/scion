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
:mod:`pcb_ext` --- Beacon extensions
====================================
"""
# SCION
from lib.packet.packet_base import HeaderBase
from lib.types import TypeBase


class BeaconExtType(TypeBase):
    """
    Constants for two types of beacon extensions.
    """
    MTU = 0
    REV = 1
    SIBRA = 2
    SIBRA_SEG_INFO = 3
    SIBRA_SEG_SOF = 4


class BeaconExtension(HeaderBase):
    """
    Base class for beacon extensions.
    """
    EXT_TYPE = None
    EXT_TYPE_STR = None
    LEN = None

    def short_desc(self):
        return ""

    def exp_ts(self):
        return None
