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
:mod:`zk` --- Main lib.zk class
===============================
"""
# Stdlib
import logging
import os
import queue
import threading
import time
from base64 import b64decode, b64encode

# External packages
from kazoo.client import KazooClient, KazooRetry, KazooState
from kazoo.exceptions import (
    ConnectionLoss,
    LockTimeout,
    NoNodeError,
    SessionExpiredError,
)
from kazoo.handlers.threading import KazooTimeoutError

# SCION
from lib.thread import kill_self, thread_safety_net
from lib.zk.errors import ZkNoConnection, ZkRetryLimit
from lib.zk.id import ZkID
from lib.zk.party import ZkParty

ZK_LOCK_FAIL = 0
ZK_LOCK_SUCCESS = 1
ZK_LOCK_ALREADY = 2


class Zookeeper(object):
    """
    A wrapper class for Zookeeper interfacing, using the `Kazoo python library
    <https://kazoo.readthedocs.org/en/latest/index.html>`_.

    As Kazoo's functionality is mostly unaware of connection-state changes,
    it requires quite a bit of delicate code to make work reliably.

    E.g. Kazoo's Lock will claim to be held, even if the Zookeeper connection
    has been lost in the meantime. This causes an immediate split-brain problem
    for anything relying on that lock for synchronization. There is also,
    unfortunately, no documented way to inform the local Lock object that the
    connection is down and therefore the Lock should be released.

    All of Kazoo's events are done via callbacks. These callbacks must not
    block. If they do, no more Kazoo events can happen.

    E.g. if a watch callback blocks, disconnection callbacks will not run.
    """

    def __init__(self, isd_as, srv_type, srv_id,
                 zk_hosts, timeout=1.0, on_connect=None,
                 on_disconnect=None):
        """
        Setup the Zookeeper connection.

        :param ISD_AS isd_as: The local ISD-AS.
        :param str srv_type:
            a service type from :const:`lib.types.ServiceType`
        :param str srv_id: Service instance identifier.
        :param list zk_hosts:
            List of Zookeeper instances to connect to, in the form of
            ``["host:port"..]``.
        :param float timeout: Zookeeper session timeout length (in seconds).
        :param on_connect:
            A function called everytime a connection is made to Zookeeper.
        :param on_disconnect:
            A function called everytime a connection is lost to Zookeeper.
        """
        self._isd_as = isd_as
        self._srv_id = b64encode(srv_id).decode("ascii")
        self._timeout = timeout
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self.prefix = "/%s/%s" % (self._isd_as, srv_type)
        # Keep track of our connection state
        self._connected = threading.Event()
        # Keep track of the kazoo lock
        self._lock = threading.Event()
        # Used to signal connection state changes
        self._state_events = queue.Queue()
        self.conn_epoch = 0
        # Kazoo parties
        self._parties = {}
        # Kazoo lock (initialised later)
        self._zk_lock = None
        self._lock_epoch = 0

        self._kazoo_setup(zk_hosts)
        self._setup_state_listener()
        self._kazoo_start()

    def _kazoo_setup(self, zk_hosts):
        """
        Create and configure Kazoo client

        :param list zk_hosts:
            List of Zookeeper instances to connect to, in the form of
            ``["host:port"..]``.
        """
        # Disable exponential back-off
        kretry = KazooRetry(max_tries=-1, max_delay=1)
        # Stop kazoo from drowning the log with debug spam:
        logger = logging.getLogger("KazooClient")
        logger.setLevel(logging.ERROR)
        # (For low-level kazoo debugging):
        # import kazoo.loggingsupport
        # logger.setLevel(kazoo.loggingsupport.BLATHER)
        self.kazoo = KazooClient(
            hosts=",".join(zk_hosts), timeout=self._timeout,
            connection_retry=kretry, logger=logger)

    def _kazoo_start(self):
        """Connect the Kazoo client to Zookeeper."""
        logging.info("Connecting to Zookeeper")
        try:
            self.kazoo.start()
        except KazooTimeoutError:
            logging.critical(
                "Timed out connecting to Zookeeper on startup, exiting")
            kill_self()

    def _setup_state_listener(self):
        """
        Spawn state listener thread, to respond to state change notifications
        from Kazoo. We use a thread, as the listener callback must not block.
        """
        threading.Thread(
            target=thread_safety_net, args=(self._state_handler,),
            name="libZK._state_handler", daemon=True).start()
        # Listener called every time connection state changes
        self.kazoo.add_listener(self._state_listener)

    def _state_listener(self, new_state):
        """Called everytime the Kazoo connection state changes."""
        self.conn_epoch += 1
        # Signal a connection state change
        logging.debug("Kazoo state changed to %s (epoch %d)",
                      new_state, self.conn_epoch)
        self._state_events.put(new_state)
        # Tell kazoo not to remove this listener:
        return False

    def _state_handler(self, initial_state="startup"):
        """
        A thread worker function to wait for Kazoo connection state changes,
        and call the relevant method.
        """
        old_state = initial_state
        while True:
            # Wait for connection state change
            new_state = self._state_events.get()

            if (new_state == KazooState.CONNECTED and not
                    self._state_events.empty()):
                # Helps prevent some state flapping.
                logging.debug("Kazoo CONNECTED ignored as the events "
                              "queue is not empty.")
                continue
            # Short-circuit handler if the state hasn't actually changed. This
            # prooobably shouldn't happen now, so making it an error.
            if new_state == old_state:
                logging.error("Kazoo state didn't change from %s, ignoring",
                              old_state)
                continue

            logging.debug("Kazoo old state: %s, new state: %s",
                          old_state, new_state)
            old_state = new_state
            if new_state == KazooState.CONNECTED:
                self._state_connected()
            elif new_state == KazooState.SUSPENDED:
                self._state_suspended()
            else:
                self._state_lost()

    def _state_connected(self):
        """Handles the Kazoo 'connected' event."""
        # Might be first connection, or reconnecting after a problem.
        clid = self.kazoo.client_id
        if clid is None:
            # Protect against a race-condition.
            return
        try:
            zk_peer = self.kazoo._connection._socket.getpeername()
        except AttributeError:
            zk_peer = "?", "?"
        logging.debug("Connection to Zookeeper succeeded (Session: %s, ZK: [%s]:%s)",
                      hex(clid[0]), zk_peer[0], zk_peer[1])
        try:
            self.ensure_path(self.prefix, abs=True)
            # Use a copy of the dictionary values, as the dictioary is changed
            # by another thread.
            for party in list(self._parties.values()):
                party.autojoin()
        except ZkNoConnection:
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
        logging.info("Connection to Zookeeper lost")
        if self._on_disconnect:
            self._on_disconnect()

    def is_connected(self):
        """Check if there is currently a connection to Zookeeper."""
        return self._connected.is_set()

    def wait_connected(self, timeout=None):
        """
        Wait until there is a connection to Zookeeper. Log every 10s until a
        connection is available.

        :param float timeout:
            Number of seconds to wait for a ZK connection. If ``None``, wait
            forever.
        :raises:
            ZkNoConnection:
                if there's no connection to ZK after timeout has expired.
        """
        if self.is_connected():
            return
        logging.debug("Waiting for ZK connection")
        start = time.time()
        total_time = 0.0
        if timeout is None:
            next_timeout = 10.0
        while True:
            if timeout is not None:
                next_timeout = min(timeout - total_time, 10.0)
            ret = self._connected.wait(timeout=next_timeout)
            total_time = time.time() - start
            if ret:
                logging.debug("ZK connection available after %.2fs", total_time)
                return
            elif timeout is not None and total_time >= timeout:
                logging.debug("ZK connection still unavailable after %.2fs",
                              total_time)
                raise ZkNoConnection
            else:
                logging.debug("Still waiting for ZK connection (%.2fs so far)",
                              total_time)

    def ensure_path(self, path, abs=False):
        """
        Ensure that a path exists in Zookeeper.

        :param str path: Path to ensure
        :param bool abs: Is the path abolute or relative?
        :raises:
            ZkNoConnection: if there's no connection to ZK.
        """
        full_path = path
        if not abs:
            full_path = os.path.join(self.prefix, path)
        try:
            self.kazoo.ensure_path(full_path)
        except (ConnectionLoss, SessionExpiredError):
            raise ZkNoConnection from None

    def party_setup(self, prefix=None, autojoin=True):
        """
        Setup a `Kazoo Party
        <https://kazoo.readthedocs.org/en/latest/api/recipe/party.html>`_.

        Used to signal that a group of processes are in a similar state.

        :param str prefix:
            Path to create the party under. If not specified, uses the default
            prefix for this server instance.
        :param bool autojoin: Join the party if True, also on reconnect
        :return: a ZkParty object
        :rtype: ZkParty
        :raises:
            ZkNoConnection: if there's no connection to ZK.
        """
        if not self.is_connected():
            raise ZkNoConnection
        if prefix is None:
            prefix = self.prefix
        party_path = os.path.join(prefix, "party")
        self.ensure_path(party_path, abs=True)
        party = ZkParty(self.kazoo, party_path, self._srv_id, autojoin)
        self._parties[party_path] = party
        return party

    def get_lock(self, lock_timeout=None, conn_timeout=None):
        """
        Try to get the lock. Returns immediately if we already have the lock.

        :param float lock_timeout:
            Time (in seconds) to wait for lock acquisition, or ``None`` to wait
            forever (Default).
        :param float conn_timeout:
            Time (in seconds) to wait for a connection to ZK, or ``None`` to
            wait forever (Default).
        :return:
            ``ZK_LOCK_FAIL`` if getting the lock failed, ``ZK_LOCK_SUCCESS`` if the lock was
            acquired, or ``ZK_LOCK_ALREADY`` if the lock is already held by this process.
        :rtype: :class:`int`
        """
        if self._zk_lock is None:
            # First-time setup.
            lock_path = os.path.join(self.prefix, "lock")
            self._zk_lock = self.kazoo.Lock(lock_path, self._srv_id)
        elif self.have_lock():
            return ZK_LOCK_ALREADY
        self.wait_connected(timeout=conn_timeout)
        self._lock_epoch = self.conn_epoch
        if lock_timeout is None:
            # Only need to log this when we could block for a long time
            logging.debug("Trying to acquire ZK lock (epoch %d)",
                          self._lock_epoch)
        try:
            if self._zk_lock.acquire(timeout=lock_timeout):
                logging.info("Successfully acquired ZK lock (epoch %d)",
                             self._lock_epoch)
                self._lock.set()
        except (ConnectionLoss, SessionExpiredError):
            raise ZkNoConnection from None
        except LockTimeout:
            pass
        except (AttributeError, TypeError):
            # Work-around for https://github.com/python-zk/kazoo/issues/288
            pass
        if self.have_lock():
            return ZK_LOCK_SUCCESS
        return ZK_LOCK_FAIL

    def release_lock(self):
        """Release the lock."""
        self._lock.clear()
        if self._zk_lock is None:
            return
        if self.is_connected():
            try:
                self._zk_lock.release()
            except (NoNodeError, ConnectionLoss, SessionExpiredError):
                pass
        # Hack suggested by https://github.com/python-zk/kazoo/issues/2
        self._zk_lock.is_acquired = False

    def have_lock(self):
        """Check if we currently hold the lock."""
        if (self.is_connected() and
                self._lock_epoch == self.conn_epoch and
                self._lock.is_set()):
            return True
        else:
            self.release_lock()
            return False

    def wait_lock(self):
        """Wait until we hold the lock."""
        self._lock.wait()

    def get_lock_holder(self):
        """
        Return address and port of the lock holder, or None if master is not
        elected.

        :raises:
            ZkNoConnection: if there's no connection to ZK.
        """
        if self._zk_lock is None:
            return None
        try:
            contenders = self._zk_lock.contenders()
            if not contenders:
                logging.warning('No lock contenders found')
                return None
            return ZkID.from_raw(b64decode(contenders[0]))
        except (ConnectionLoss, SessionExpiredError):
            logging.warning("Disconnected from ZK.")
            raise ZkNoConnection from None

    def retry(self, desc, f, *args, _retries=4, _timeout=10.0, **kwargs):
        """
        Execute a given operation, retrying it if fails due to connection
        problems.

        :param str desc: Description of the operation
        :param function f: Function to call, passing in \*args and \*\*kwargs
        :param int _retries:
            Number of times to retry the operation, or `None` to retry
            indefinitely.
        :param float _timeout:
            Number of seconds to wait for a connection, or `None` to wait
            indefinitely.
        """
        count = -1
        while True:
            count += 1
            if _retries is not None and count > _retries:
                break
            try:
                self.wait_connected(timeout=_timeout)
            except ZkNoConnection:
                logging.warning("%s: No connection to ZK", desc)
                continue
            try:
                return f(*args, **kwargs)
            except ZkNoConnection:
                logging.warning("%s: Connection to ZK dropped", desc)
        raise ZkRetryLimit("%s: Failed %s times, giving up" %
                           (desc, 1+_retries))
