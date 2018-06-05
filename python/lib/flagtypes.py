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
    def __init__(self, val_names):
        self._rev = {}
        for val, *names in val_names:
            setattr(self, names[0], val)
            self._rev[val] = names

    def to_str(self, flags):
        ret = []
        for val in sorted(self._rev):
            true, false = self._rev[val]
            if flags & val:
                ret.append(true)
            elif false:
                ret.append(false)
        return "|".join(ret) or "None"


PathSegFlags = FlagBase((
    (1, "SIBRA", "SCION"),
))

InfoOFFlags = FlagBase((
    (1, "CONS_DIR", "NOT_CONS_DIR"),
    (2, "SHORTCUT", ""),
    (4, "PEER_SHORTCUT", ""),
))

HopOFFlags = FlagBase((
    # Used to signal that this HOF is at a cross-over point between segments,
    # and needs special provcessing. Set by the endhost.
    (1, "XOVER", ""),
    # Marks HOFs that aren't used for routing, just for mac verification.
    (2, "VERIFY_ONLY", ""),
    # Used by an AS to disallow local delivery of packets (AKA a forward-only
    # AS).
    (4, "FORWARD_ONLY", ""),
    # Flag used with an SVC address to redirect a packet to the local service at
    # a given hop. Set by the endhost.
    (8, "RECURSE", ""),
))

TCPFlags = FlagBase((
    (1, "ONEHOPPATH", ""),
))
