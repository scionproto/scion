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
import abc
import threading
from collections import OrderedDict


class CacheEmptyException(Exception):
    """Cache is empty exception."""


class Cache(metaclass=abc.ABCMeta):
    """
    Thread-safe cache with auto expiration of entries. Subclasses have to implement
    their own way how to validate an entry.
    """

    def __init__(self, capacity=1000):  # pragma: no cover
        self._cache = OrderedDict()
        self._lock = threading.RLock()
        self._capacity = capacity

    def __contains__(self, key):  # pragma: no cover
        with self._lock:
            stored_entry = self._cache.get(key)
            return stored_entry and not self._expire_entry(key, stored_entry)

    def __getitem__(self, key):  # pragma: no cover
        return self.get(key)

    def __len__(self):  # pragma: no cover
        return len(self._cache)

    def popleft(self):  # pragma: no cover
        return self.popitem(last=False)

    def popitem(self, last=True):
        """
        Returns and removes a (key, value) pair. The pairs are returned in
        LIFO order if last is true or FIFO order if false.
        """
        with self._lock:
            # Pop items until a non expired one is returned or the dictionary is empty.
            while True:
                try:
                    key, entry = self._cache.popitem(last=last)
                except KeyError:
                    raise CacheEmptyException
                if self._validate_entry(entry):
                    return key, entry

    def get(self, key, default=None):
        with self._lock:
            try:
                entry = self._cache[key]
            except KeyError:
                return default
            if not self._expire_entry(key, entry):
                return entry
            return default

    def add(self, entry, key=None):
        """
        Adds entry to the cache. The caller can optionally provide a key under which
        the entry will be stored. If no key is provided, a key for the entry will be
        calculated. In case the cache is at its capacity, the oldest entry is replaced.

        :returns: True if the entry was added, False if a newer entry was present.
        """
        if not self._validate_entry(entry):
            return False
        with self._lock:
            key = key or self._mk_key(entry)
            stored_entry = self.get(key)
            if not stored_entry:
                # Try to free up space in case the cache reaches the cap limit by removing
                # expired entries.
                if len(self._cache) >= self._capacity:
                    for k, e in list(self._cache.items()):
                        self._expire_entry(k, e)
                # Couldn't free up enough space, evict the oldest entry.
                if len(self._cache) >= self._capacity:
                    self._cache.popitem(last=False)
                self._cache[key] = entry
                return True
            if self._is_newer(entry, stored_entry):
                self._cache[key] = entry
                return True
            return False

    def clear(self):  # pragma: no cover
        with self._lock:
            self._cache = OrderedDict()

    def _mk_key(self, entry):  # pragma: no cover
        return hash(entry)

    def _is_newer(self, e1, e2):  # pragma: no cover
        return e1 > e2

    def _expire_entry(self, key, entry):  # pragma: no cover
        """Removes an expired entry from the cache."""
        if not self._validate_entry(entry):
            del self._cache[key]
            return True
        return False

    @abc.abstractmethod
    def _validate_entry(self, entry):  # pragma: no cover
        raise NotImplementedError
