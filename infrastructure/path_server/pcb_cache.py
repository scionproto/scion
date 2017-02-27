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
:mod:`pcb_cache` --- PCB cache for recently handed out PCBs.
============================================================
"""
# Stdlib
import threading

# External packages
from external.expiring_dict import ExpiringDict

# SCION
from lib.defines import HASHTREE_EPOCH_TIME


class PCBCache:
    """
    Short lived path segment cache. Caches segments that contain revocations
    for peer interfaces. This class is thread-safe.
    """

    def __init__(self, capacity=100):
        self._cache = ExpiringDict(capacity, HASHTREE_EPOCH_TIME)
        self._lock = threading.Lock()

    def get(self, key, default=None):
        with self._lock:
            return self._cache.get(key, default)

    def add(self, key, pcb):
        with self._lock:
            self._cache[key] = pcb

    def invalidate_entry(self, key):
        """Removes an entry if it exists."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def update_with_rev(self, rev_info):
        """
        Updates the segments in the pcb_cache with a new revocation, if the
        revocation is for a peering interface in that segment.
        """
        with self._lock:
            for segment in self._cache.values():
                self._update_segment_with_rev(segment, rev_info)

    def _update_segment_with_rev(self, segment, rev_info):
        for asm in segment.iter_asms():
            if asm.isd_as() != rev_info.isd_as():
                continue
            for pcbm in asm.iter_pcbms(start=1):
                hof = pcbm.hof()
                if rev_info.p.ifID in [hof.ingress_if, hof.egress_if]:
                    segment.add_rev_infos([rev_info.copy()])
                    return
