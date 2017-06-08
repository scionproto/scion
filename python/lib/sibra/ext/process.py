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
:mod:`process` --- Helper for processing SIBRA packets in transit.
=================================================================
"""


class ProcessMeta(object):  # pragma: no cover
    """
    Encasulates meta-data needed to process a SIBRA extension in transit

    `dir_fwd` is used to indicate the direction of travel relative to the local
    node. Forward means the packet is at an egress router, reverse means it's at
    an ingress router.
    """
    def __init__(self, state, spkt, from_local_as, key, fwd):
        self.spkt = spkt
        self.state = state
        self.from_local_as = from_local_as
        self.key = key
        self.dir_fwd = fwd == from_local_as
