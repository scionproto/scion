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
:mod:`rev_cache` --- Cache for revocations
==========================================
"""
# Stdlib
import threading


class CacheFullException(Exception):
    """Cache is full exception."""


class Cache:
    """Thread-safe cache with auto expiration of entries."""

    def __init__(self, capacity=1000):  # pragma: no cover
        self._cache = {}
        self._lock = threading.RLock()
        self._capacity = capacity

    def __contains__(self, key):  # pragma: no cover
        with self._lock:
            stored_entry = self._cache.get(key)
            return stored_entry and not self._expire_entry(stored_entry)

    def __getitem__(self, key):  # pragma: no cover
        return self.get(key)

    def get(self, key, default=None):
        with self._lock:
            try:
                entry = self._cache[key]
            except KeyError:
                return default
            if not self._expire_entry(entry):
                return entry
            return default

    def add(self, entry):
        """
        Adds entry to the cache.

        :returns: True if the entry was added, False if a newer entry was present.
        :raises: CacheFullException if the cache is full.
        """
        if not self._validate_entry(entry):
            return False
        with self._lock:
            key = self._mk_key(entry)
            stored_entry = self.get(key)
            if not stored_entry:
                # Try to free up space in case the cache reaches the cap limit.
                if len(self._cache) >= self._capacity:
                    for e in list(self._cache.values()):
                        self._expire_entry(e)
                # Couldn't free up enough space...
                if len(self._cache) >= self._capacity:
                    raise CacheFullException(
                        "Cache at max capacity (%d)." % self._capacity)
                self._cache[key] = entry
                return True
            if self._is_newer(entry, stored_entry):
                self._cache[key] = entry
                return True
            return False

    def _mk_key(self, entry):  # pragma: no cover
        return hash(entry)

    def _is_newer(self, e1, e2):  # pragma: no cover
        return e1 > e2

    def _expire_entry(self, entry):  # pragma: no cover
        """Removes an expired entry from the cache."""
        if not self._validate_entry(entry):
            del self._cache[self._mk_key(entry)]
            return True
        return False

    def _validate_entry(self, entry):  # pragma: no cover
        raise NotImplementedError
