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
:mod:`types` --- DRKey types
============================

For all type classes used in DRKey
"""

# External

# SCION
from lib.types import TypeBase

###########################
# DRKey types
###########################


class DRKeyProtoReqType(TypeBase):
    AS_TO_AS = 0
    AS_TO_HOST = 1
    HOST_TO_HOST = 2
    AS_TO_HOST_PAIR = 3


class DRKeyProtocols(TypeBase):
    OPT = 0
    SCMP_AUTH = 1
