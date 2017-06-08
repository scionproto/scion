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
:mod:`core` --- core SIBRA service daemon
=========================================
"""

# SCION
from lib.types import PathSegmentType as PST
from sibra_server.main import SibraServerBase


class SibraServerCore(SibraServerBase):
    PST_TYPE = PST.CORE

    def _manage_core(self, link):
        if self.addr.isd_as.int() < link.neigh.int():
            # It's the responsibility of the lower ISD-AS to create/maintain the
            # core steady path.
            self._add_renew(link)
