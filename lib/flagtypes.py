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
:mod:`flagtypes` --- SCION flag types
=====================================

For all flags types that are used in multiple parts of the infrastructure.
"""


class FlagBase(object):  # pragma: no cover
    def __init__(self, name_vals):
        self._rev = {}
        for name, val in name_vals:
            setattr(self, name, val)
            self._rev[val] = name

    def to_str(self, flags):
        ret = []
        for val in sorted(self._rev):
            if flags & val:
                ret.append(self._rev[val])
        if not ret:
            return "None"
        return "|".join(ret)


PathSegFlags = FlagBase((
    ("SIBRA", 1),
))
