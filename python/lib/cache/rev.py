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
:mod:`rev` --- Cache for revocations
====================================
"""
# SCION
from lib.crypto.hash_tree import ConnectedHashTree
from lib.cache.base import Cache


class RevCache(Cache):  # pragma: no cover
    def _mk_key(self, rev_info):
        """Returns the key for a RevocationInfo object."""
        return (rev_info.isd_as(), rev_info.p.ifID)

    def _is_newer(self, rev1, rev2):
        return rev1.p.epoch > rev2.p.epoch

    def _validate_entry(self, rev_info):
        return ConnectedHashTree.verify_epoch(rev_info.p.epoch)
