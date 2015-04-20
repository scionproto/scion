# Copyright 2015 ETH Zurich

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`zookeeper` --- Library for interfacing with Zookeeper
========================================================================
"""

import os.path
import logging
import threading
import time

from kazoo.client import (KazooClient, KazooState, KazooRetry)
from kazoo.handlers.threading import TimeoutError
from kazoo.exceptions import (LockTimeout, SessionExpiredError,
                              NoNodeError, ConnectionLoss)
from lib.util import (kill_self, thread_safety_net)
from lib.packet.pcb import PathSegment

class ZkConnectionLoss(Exception):
    """Connection to Zookeeper is lost"""
    pass

class ZkNoNodeError(Exception):
    """A node doesn't exist"""
    pass

class Zookeeper(object):
    """
    A wrapper class for Zookeeper interfacing, using the `Kazoo python library
    <https://kazoo.readthedocs.org/en/latest/index.html>`_.

    As Kazoo's functionality is mostly unaware of connection-state changes,
    it requires quite a bit of delicate code to make work reliably.

    E.g. Kazoo's Lock will claim to be held, even if the Zookeeper connection
    has been lost in the meantime. This causes an immediate split-brain problem
    for anything relying on that lock for synchronization. This is also,
    unfortunately, no way to inform the local Lock object that the connection
    is down and therefore the Lock should be released.

    All of Kazoo's events are done via callbacks. These callbacks must not
    block. If they do, no more Kazoo events can happen.

    E.g. if a watch callback blocks, disconnection callbacks will not run.
    """

    def __init__(self, isd_id, ad_id, srv_name, srv_id,
                 zk_hosts, timeout=1.0, on_connect=None,
                 on_disconnect=None, ensure_paths=()):
        """
        Setup the Zookeeper connection.

        :param int isd_id: The ID of the current ISD.
        :param int ad_id: The ID of the current AD.
        :param str srv_name: Short description of the service. E.g. ``"bs"`` for
                             Beacon server.
        :param str srv_id: The ID of the service. E.g. host the service is
                           running on.
        :param list zk_hosts: List of Zookeeper instances to connect to, in the
                              form of ``["host:port"..]``.
        :param float timeout: Zookeeper session timeout length (in seconds).
        :param on_connect: A function called everytime a connection is made to
                           Zookeeper.
        :param on_disconnect: A function called everytime a connection is lost
                              to Zookeeper.
        :param tuple ensure_paths: A tuple of ZK paths to ensure exist on
                                   connect.
        """
        self._isd_id = isd_id
        self._ad_id = ad_id
        self._srv_name = srv_name
        self._srv_id = srv_id
        self._timeout = timeout
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self._ensure_paths = ensure_paths

        retry = KazooRetry(max_tries=-1, max_delay=1)

        self._prefix = "/ISD%d-AD%d/%s" % (self._isd_id,
                                           self._ad_id,
                                           self._srv_name)
        self._zk = KazooClient(hosts=",".join(zk_hosts),
                               timeout=self._timeout,
                               connection_retry=retry)
        # Stop kazoo from drowning the log with debug spam:
        self._zk.logger.setLevel(logging.ERROR)
        # FIXME(kormat): remove once stable:
        # (For low-level kazoo debugging)
        #import kazoo.loggingsupport
        #self._zk.logger.setLevel(kazoo.loggingsupport.BLATHER)

        # Keep track of our connection state
        self._connected = threading.Event()
        # Kazoo party (initialised later)
        self._party = None
        # Keep track of the kazoo lock
        self._lock = threading.Event()
        # Kazoo lock (initialised later)
        self._zk_lock = None
        # Used to signal connection state changes
        self._state_event = threading.Semaphore(value=0)
        # Use a thread to respond to state changes, as the listener callback
        # must not block.
        threading.Thread(target=self._state_handler, daemon=True).start()
        # Listener called every time connection state changes
        self._zk.add_listener(self._state_listener)

        logging.info("Connecting to Zookeeper")
        try:
            self._zk.start()
        except TimeoutError:
            logging.critical(
                    "Timed out connecting to Zookeeper on startup, exiting")
            kill_self()

    def _state_listener(self, new_state):
        """
        Called everytime the Kazoo connection state changes.
        """
        # Signal a connection state change
        self._state_event.release()
        # Tell kazoo not to remove this listener:
        return False

    @thread_safety_net("_state_handler")
    def _state_handler(self):
        """
        A thread worker function to wait for Kazoo connection state changes,
        and call the relevant method.
        """
        self._old_state = "startup"
        while True:
            # Wait for connection state change
            self._state_event.acquire()
            # Short-circuit handler if the state hasn't actually changed
            if self._old_state == self._zk.state:
                continue
            logging.debug("Kazoo old state: %s, new state: %s",
                          self._old_state, self._zk.state)
            self._old_state = self._zk.state
            if self._zk.state == KazooState.CONNECTED:
                self._state_connected()
            elif self._zk.state == KazooState.SUSPENDED:
                self._state_suspended()
            else:
                self._state_lost()

    def _state_connected(self):
        """
        Handles the Kazoo 'connected' event.
        """
        # Might be first connection, or reconnecting after a problem.
        logging.debug("Connection to Zookeeper succeeded")
        try:
            self._zk.ensure_path(self._prefix)
            for path in self._ensure_paths:
                self._zk.ensure_path(os.path.join(self._prefix, path))
        except (ConnectionLoss, SessionExpiredError):
            return
        self._connected.set()
        if self._on_connect:
            self._on_connect()

    def _state_suspended(self):
        """
        Handles the Kazoo 'connection suspended' event.

        This means that the connection to Zookeeper is down.
        """
        self._connected.clear()
        self._lock.clear()
        logging.info("Connection to Zookeeper suspended")
        if self._on_disconnect:
            self._on_disconnect()

    def _state_lost(self):
        """
        Handles the Kazoo 'connection lost' event.

        This means that the Zookeeper session is lost, so all setup needs to be
        re-done on connect.
        """
        self._connected.clear()
        self._lock.clear()
        logging.info("Connection to Zookeeper lost")
        if self._on_disconnect:
            self._on_disconnect()

    def is_connected(self):
        """
        Check if there is currently a connection to Zookeeper.
        """
        return self._connected.is_set()

    def wait_connected(self):
        """
        Wait until there is a connection to Zookeeper.
        """
        self._connected.wait()

    def join_party(self):
        """
        Join a `Kazoo Party
        <https://kazoo.readthedocs.org/en/latest/api/recipe/party.html>`_.

        Used to signal that a group of processes are in a similar state.

        :raises:
            ZkConnectionLoss: if the connection to ZK drops
        """
        if not self.is_connected():
            raise ZkConnectionLoss
        if self._party is None:
            # Initialise the service party
            party_path = os.path.join(self._prefix, "party")
            self._party = self._zk.Party(party_path, self._srv_id)
        try:
            self._party.join()
        except ConnectionLoss:
            raise ZkConnectionLoss
        logging.debug("Joined party, members are: %s", list(self._party))

    def watch_children(self, path, func):
        """
        Register a callback function to be called when a path's children
        change. This watch does not persist across disconnections.

        :param str path: The path to watch.
        :param function func: The function to call.
        :raises:
            ZkConnectionLoss: if the connection to ZK drops.
        """
        if not self.is_connected():
            raise ZkConnectionLoss
        path = os.path.join(self._prefix, path)
        try:
            self._zk.exists(path)
            self._zk.ChildrenWatch(path, func=func, allow_session_lost=False)
        except ConnectionLoss:
            raise ZkConnectionLoss

    def get_lock(self, timeout=60.0):
        """
        Try to get the lock. Returns immediately if we already have the lock.

        :param float timeout: Time (in seconds) to wait for lock acquisition,
                              or ``None`` to wait forever.
        :type timeout: float or None.
        :return: ``True`` if we got the lock, or already had it, otherwise
                 ``False``.
        :rtype: :class:`bool`
        """
        if self._zk_lock is None:
            # First-time setup.
            logging.debug("get_lock: init lock")
            lock_path = os.path.join(self._prefix, "lock")
            self._zk_lock = self._zk.Lock(lock_path, self._srv_id)
        if not self.is_connected():
            self._lock.clear()
            # Hack suggested by https://github.com/python-zk/kazoo/issues/2
            self._zk_lock.is_acquired = False
            logging.debug("get_lock: not connected")
            return False
        if self._lock.is_set():
            # We already have the lock
            logging.debug("get_lock: already have lock")
            return True
        else:
            # Hack suggested by https://github.com/python-zk/kazoo/issues/2
            self._zk_lock.is_acquired = False
        try:
            logging.debug("get_lock: try acquire lock")
            if self._zk_lock.acquire(timeout=timeout):
                logging.debug("get_lock: acquired lock")
                self._lock.set()
            else:
                logging.debug("get_lock: failed to acquire lock")
        except (LockTimeout, ConnectionLoss, SessionExpiredError) as e:
            logging.debug("get_lock: exception acquiring lock: %s", e)
            pass
        ret = self._have_lock()
        logging.debug("get_lock: do we have the lock? %s", ret)
        return ret

    def _have_lock(self):
        """
        Check if we currently hold the lock
        """
        return self.is_connected() and self._lock.is_set()

    def wait_lock(self):
        """
        Wait until we hold the lock
        """
        self._lock.wait()

    def store_shared_item(self, path, name, value):
        """
        Store an item in a shared path.

        :param str path: The path to store the item in. E.g. ``"shared"``
        :param str name: A prefix for the item entry. E.g. ``"pcb"``
        :param bytes value: The value to store in the item.
        :raises:
            ZkConnectionLoss: if the connection to ZK drops
        """
        if not self.is_connected():
            raise ZkConnectionLoss
        path = os.path.join(self._prefix, path)
        try:
            self._zk.create("%s/%s" % (path, name), value, sequence=True)
        except (ConnectionLoss, SessionExpiredError):
            raise ZkConnectionLoss

    def get_shared_item(self, path, entry):
        """
        Retrieve a specific item from a shared path.

        :param str path: The path the item is stored in. E.g. ``"shared"``
        :param str entry: The name of the entry. E.g. ``"pcb0000002046"``
        :return: The value of the item
        :rtype: :class:`bytes`
        :raises:
            ZkConnectionLoss: if the connection to ZK drops
            ZkNoNodeError: if the entry does not exist
        """
        if not self.is_connected():
            raise ZkConnectionLoss
        entry_path = os.path.join(self._prefix, path, entry)
        try:
            data, _ = self._zk.get(entry_path)
        except NoNodeError:
            raise ZkNoNodeError
        except (ConnectionLoss, SessionExpiredError):
            raise ZkConnectionLoss
        return data

    def get_shared_entries(self, path):
        """
        List the items in a shared path.

        :param str path: The path the items are stored in. E.g.  ``"shared"``
        :return: The value of the item, if successfully retrieved, otherwise
                 ``None``
        :rtype: :class:`bytes` or ``None``
        :raises:
            ZkConnectionLoss: if the connection to ZK drops
        """
        if not self.is_connected():
            return []
        path = os.path.join(self._prefix, path)
        try:
            entries = self._zk.get_children(path)
        except ConnectionLoss:
            raise ZkConnectionLoss
        return entries

    def move_shared_items(self, src, dest):
        """
        Move items from one shared path to another

        :param str src: The path of the source
        :param str dest: The path of the destination
        :raises:
            ZkConnectionLoss: if the connection to ZK drops
        """
        # TODO(kormat): move constants to proper place
        chunk_size = 50
        max_entries = 50
        if not self.is_connected():
            raise ZkConnectionLoss
        src = os.path.join(self._prefix, src)
        dest = os.path.join(self._prefix, dest)
        try:
            src_entries = self._zk.get_children(src)
            dest_entries = self._zk.get_children(dest)
            # First, copy `max_entries` src entries across, deleting as we go
            # Delete in chunks, as every operation will trigger watch callbacks
            # for all BSes in the cluster, and deleting them all at once causes
            # ZK to timeout.
            moved = 0
            for i in range(0, len(src_entries), chunk_size):
                trans = self._zk.transaction()
                for entry in src_entries[i:i+chunk_size]:
                    if moved < max_entries:
                        data, stat = self._zk.get("%s/%s" % (src, entry))
                        trans.create("%s/%s" % (dest, entry), data)
                    trans.delete("%s/%s" % (src, entry))
                    moved += 1
                trans.commit()
                logging.debug("Moved %d entries", moved)
            # Second, delete all pre-existing dest entries
            deleted = 0
            for i in range(0, len(dest_entries), chunk_size):
                trans = self._zk.transaction()
                for entry in dest_entries[i:i+chunk_size]:
                    trans.delete("%s/%s" % (dest, entry))
                    deleted += 1
                trans.commit()
                logging.debug("Deleted %d entries", deleted)
        except ConnectionLoss:
            raise ZkConnectionLoss

