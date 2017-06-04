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
:mod:`cache` --- Zookeeper shared cache.
========================================
"""
# Stdlib
import logging
import os.path
import time
from collections import deque

from kazoo.exceptions import (
    ConnectionLoss,
    NoNodeError,
    NodeExistsError,
    SessionExpiredError,
)

# SCION
from lib.zk.errors import ZkNoConnection, ZkNoNodeError


class ZkSharedCache(object):
    """Class for handling ZK shared caches."""
    def __init__(self, zk, path, handler):  # pragma: no cover
        """
        :param Zookeeper zk: A Zookeeper instance.
        :param str path: The path of the shared cache.
        :param function handler: Handler for a list of cache entries.
        """
        self._zk = zk
        self._kazoo = zk.kazoo
        self._path = os.path.join(self._zk.prefix, path)
        self._handler = handler
        # A mapping from entry name to the timestamp it was first encountered
        # at.
        self._entries = {}
        # A queue for the store() thread to inform the process()/expire() thread
        # about newly created entries.
        self._incoming_entries = deque()

    def store(self, name, value):
        """
        Store an entry in the cache.

        :param str name: Name of the entry. E.g. ``"item01"``.
        :param bytes value: The value of the entry.
        :raises:
            ZkNoConnection: if there's no connection to ZK.
        """
        if not self._zk.is_connected():
            raise ZkNoConnection
        full_path = os.path.join(self._path, name)
        # First, assume the entry already exists (the normal case)
        try:
            self._kazoo.set(full_path, value)
            self._incoming_entries.append((name, time.time()))
            return
        except NoNodeError:
            pass
        except (ConnectionLoss, SessionExpiredError):
            raise ZkNoConnection from None
        # Entry doesn't exist, so create it instead.
        try:
            self._kazoo.create(full_path, value, makepath=True)
            self._incoming_entries.append((name, time.time()))
            return
        except NodeExistsError:
            # Entry was created between our check and our create, so assume that
            # the contents are recent, and return without error.
            pass
        except (ConnectionLoss, SessionExpiredError):
            raise ZkNoConnection from None

    def process(self):
        """
        Look for new/updated entries, and pass them to the registered handler.

        :raises:
            ZkNoConnection: if there's no connection to ZK.
        """
        if not self._zk.is_connected():
            raise ZkNoConnection
        # Update self._entries with any new entries we have created via store()
        while self._incoming_entries:
            name, ts = self._incoming_entries.popleft()
            # If the entry already exists, don't change it.
            self._entries.setdefault(name, ts)
        previous = set(self._entries)
        current = set(self._list_entries())
        for entry in previous - current:
            # Remove stale entry names
            del self._entries[entry]
        count = self._handle_entries(current - previous)
        if count:
            logging.debug("Processed %d new entries from %s", count,
                          self._path)

    def _get(self, name):
        """
        Get an entry from the cache.

        :param str name: Name of the entry. E.g. ``"pcb0000002046"``.
        :return: The value of the entry.
        :rtype: :class:`bytes`
        :raises:
            ZkNoConnection: if there's no connection to ZK.
            ZkNoNodeError: if the entry does not exist.
        """
        full_path = os.path.join(self._path, name)
        try:
            data, _ = self._kazoo.get(full_path)
        except (ConnectionLoss, SessionExpiredError):
            raise ZkNoConnection from None
        except NoNodeError:
            self._entries.pop(name, None)
            raise ZkNoNodeError from None
        self._entries.setdefault(name, time.time())
        return data

    def _list_entries(self):
        """
        List all entries.

        :return: A set of entry names.
        :rtype: set(:class:`str`, ..)
        :raises:
            ZkNoConnection: if there's no connection to ZK.
        """
        try:
            return set(self._kazoo.get_children(self._path))
        except (ConnectionLoss, SessionExpiredError):
            raise ZkNoConnection from None
        except NoNodeError:
            # This means the cache dir hasn't been created yet by store(),
            # so just return an empty set.
            return set()

    def _handle_entries(self, entry_names):
        """
        Retrieve the data for a set of entries, and pass it to the registered
        handler.

        :param set entry_names: Entry names.
        :returns: Number of entries passed to handler.
        """
        data = []
        for name in entry_names:
            try:
                data.append(self._get(name))
            except ZkNoConnection:
                logging.warning("Unable to retrieve entry from shared "
                                "path %s: no connection to ZK" % self._path)
                break
            except ZkNoNodeError:
                logging.debug("Unable to retrieve entry from shared cache: "
                              "no such entry (%s/%s)" % (self._path, name))
                continue
        self._handler(data)
        return len(data)

    def expire(self, ttl):
        """
        Delete entries first seen more than `ttl` seconds ago.

        :param float ttl:
            Age (in seconds) after which cache entries should be removed.
        :raises:
            ZkNoConnection: if there's no connection to ZK.
            ZkNoNodeError: if a node disappears unexpectedly.
        """
        if not self._zk.is_connected():
            raise ZkNoConnection
        now = time.time()
        count = 0
        for entry, ts in self._entries.items():
            if now - ts > ttl:
                full_path = os.path.join(self._path, entry)
                count += 1
                try:
                    self._kazoo.delete(full_path)
                except NoNodeError:
                    # This shouldn't happen, so raise an exception if it does.
                    raise ZkNoNodeError
                except (ConnectionLoss, SessionExpiredError):
                    raise ZkNoConnection from None
        if count:
            logging.debug("Expired %d old entries from %s", count, self._path)
