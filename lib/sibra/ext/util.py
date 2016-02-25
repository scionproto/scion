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
:mod:`util` --- SIBRA extension utilities
=========================================
"""
# SCION
from lib.sibra.ext.ext import FLAG_STEADY
from lib.sibra.ext.steady import SibraExtSteady
from lib.sibra.ext.ephemeral import SibraExtEphemeral


def parse_sibra_ext(raw):  # pragma: no cover
    flag = raw[0]
    if flag & FLAG_STEADY:
        return SibraExtSteady(raw)
    else:
        return SibraExtEphemeral(raw)
