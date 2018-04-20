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
:mod:`zk_test` --- lib.zk.zk unit tests
=======================================
"""
# Stdlib
import logging
from unittest.mock import MagicMock, call, patch

# External packages
import nose
import nose.tools as ntools
from kazoo.client import KazooState
from kazoo.exceptions import (
    ConnectionLoss,
    LockTimeout,
    NoNodeError,
    SessionExpiredError,
)
from kazoo.handlers.threading import KazooTimeoutError

# SCION
from lib.thread import thread_safety_net
from lib.zk.errors import ZkNoConnection
from lib.zk.zk import ZkRetryLimit, Zookeeper
from test.testcommon import SCIONTestError, create_mock


class BaseZookeeper(object):
    """
    Base class for lib.zk.zk.Zookeeper unit tests
    """
    default_args = ["1-ff00:0:301", "srvtype", b"srvid"]
    default_hosts = ["host1:9521", "host2:339"]

    def _init_basic_setup(self, **kwargs):
        all_args = self.default_args + [self.default_hosts]
        return Zookeeper(*all_args, **kwargs)


class TestZookeeperInit(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper.__init__
    """
    @patch("lib.zk.zk.Zookeeper._kazoo_start", autospec=True)
    @patch("lib.zk.zk.Zookeeper._setup_state_listener", autospec=True)
    @patch("lib.zk.zk.Zookeeper._kazoo_setup", autospec=True)
    @patch("lib.zk.zk.queue.Queue", autospec=True)
    @patch("lib.zk.zk.threading.Event", autospec=True)
    def test_full(self, event, queue, ksetup, listener, kstart):
        # Setup and call
        event.side_effect = ["event0", "event1"]
        inst = self._init_basic_setup(
            timeout=4.5, on_connect="on_conn", on_disconnect="on_dis")
        # Tests
        ntools.eq_(inst._isd_as, "1-ff00:0:301")
        ntools.eq_(inst._srv_id, 'c3J2aWQ=')
        ntools.eq_(inst._timeout, 4.5)
        ntools.eq_(inst._on_connect, "on_conn")
        ntools.eq_(inst._on_disconnect, "on_dis")
        ntools.eq_(inst.prefix, "/1-ff00:0:301/srvtype")
        ntools.eq_(inst._connected, "event0")
        ntools.eq_(inst._lock, "event1")
        queue.assert_called_once_with()
        ntools.eq_(inst._state_events, queue.return_value)
        ntools.eq_(inst.conn_epoch, 0)
        ntools.eq_(inst._parties, {})
        ntools.eq_(inst._zk_lock, None)
        ksetup.assert_called_once_with(inst, self.default_hosts)
        listener.assert_called_once_with(inst)
        kstart.assert_called_once_with(inst)

    @patch("lib.zk.zk.Zookeeper._kazoo_start", autospec=True)
    @patch("lib.zk.zk.Zookeeper._setup_state_listener", autospec=True)
    @patch("lib.zk.zk.Zookeeper._kazoo_setup", autospec=True)
    @patch("lib.zk.zk.threading.Semaphore", autospec=True)
    @patch("lib.zk.zk.threading.Event", autospec=True)
    def test_defaults(self, event, semaphore, ksetup, listener, kstart):
        # Setup and call
        inst = self._init_basic_setup()
        # Tests
        ntools.eq_(inst._timeout, 1.0)
        ntools.eq_(inst._on_connect, None)
        ntools.eq_(inst._on_disconnect, None)


class TestZookeeperKazooSetup(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper._kazoo_setup
    """
    @patch("lib.zk.zk.KazooClient", autospec=True)
    @patch("lib.zk.zk.logging.getLogger", autospec=True)
    @patch("lib.zk.zk.KazooRetry", autospec=True)
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test(self, init, kretry, getlogger, kclient):
        # Setup
        inst = self._init_basic_setup()
        inst._timeout = 7.9
        logger = create_mock(["setLevel"])
        getlogger.return_value = logger
        # Call
        inst._kazoo_setup(["host0", "host1"])
        # Tests
        kretry.assert_called_once_with(max_tries=-1, max_delay=1)
        getlogger.assert_called_once_with("KazooClient")
        logger.setLevel.assert_called_once_with(logging.ERROR)
        kclient.assert_called_once_with(
            hosts="host0,host1", timeout=7.9,
            connection_retry=kretry.return_value, logger=getlogger.return_value)
        ntools.eq_(inst.kazoo, kclient.return_value)


class TestZookeeperKazooStart(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper._kazoo_start
    """
    @patch("lib.zk.zk.logging", autospec=True)
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test(self, init, logging_):
        # Setup
        inst = self._init_basic_setup()
        inst.kazoo = create_mock(["start"])
        # Call
        inst._kazoo_start()
        # Tests
        inst.kazoo.start.assert_called_once_with()

    @patch("lib.zk.zk.kill_self", autospec=True)
    @patch("lib.zk.zk.logging", autospec=True)
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_timeout(self, init, logging_, kill_self):
        # Setup
        inst = self._init_basic_setup()
        inst.kazoo = create_mock(["start"])
        inst.kazoo.start.side_effect = KazooTimeoutError
        # Call
        inst._kazoo_start()
        # Tests
        kill_self.assert_called_once_with()


class TestZookeeperSetupStateListener(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper._setup_state_listener
    """
    @patch("lib.zk.zk.threading.Thread", autospec=True)
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test(self, init, thread):
        # Setup
        inst = self._init_basic_setup()
        thread.return_value = create_mock(["start"])
        inst.kazoo = create_mock(["add_listener"])
        # Call
        inst._setup_state_listener()
        # Tests
        thread.assert_called_once_with(target=thread_safety_net,
                                       args=(inst._state_handler,),
                                       name="libZK._state_handler", daemon=True)
        thread.return_value.start.assert_called_once_with()
        inst.kazoo.add_listener(inst._state_listener)


class TestZookeeperStateListener(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper._state_listener
    """
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test(self, init):
        # Setup
        inst = self._init_basic_setup()
        inst._state_events = create_mock(["put"])
        inst.conn_epoch = 47
        # Call
        ntools.eq_(inst._state_listener("statist"), False)
        # Tests
        inst._state_events.put.assert_called_once_with("statist")
        ntools.eq_(inst.conn_epoch, 48)


class TestZookeeperStateHandler(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper._state_handler
    """
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_flapping(self, init):
        # Setup
        inst = self._init_basic_setup()
        inst._state_events = create_mock(["get", "empty"])
        # Setup inst._state_events.get to allow a single iteration of the loop
        inst._state_events.get.side_effect = [KazooState.CONNECTED]
        inst._state_events.empty.return_value = False
        inst._state_connected = create_mock()
        # Call
        ntools.assert_raises(StopIteration, inst._state_handler)
        # Tests
        inst._state_events.get.assert_has_calls([call()] * 2)
        ntools.assert_false(inst._state_connected.called)

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def _check(self, old_state, new_state, init):
        # Setup
        inst = self._init_basic_setup()
        inst._state_events = create_mock(["get", "empty"])
        # Setup inst._state_events.get to allow a single iteration of the loop
        inst._state_events.get.side_effect = [new_state]
        inst._state_connected = create_mock()
        inst._state_suspended = create_mock()
        inst._state_lost = create_mock()
        # Call
        ntools.assert_raises(StopIteration, inst._state_handler,
                             initial_state=old_state)
        # Tests
        connected = suspended = lost = 0
        if old_state == new_state:
            # In this case none of the state change handlers should be called
            pass
        elif new_state == KazooState.CONNECTED:
            connected = 1
        elif new_state == KazooState.SUSPENDED:
            suspended = 1
        elif new_state == KazooState.LOST:
            lost = 1
        else:
            raise SCIONTestError("Invalid new state")
        ntools.eq_(inst._state_connected.call_count, connected)
        ntools.eq_(inst._state_suspended.call_count, suspended)
        ntools.eq_(inst._state_lost.call_count, lost)

    def test_basic(self):
        test_inputs = (
            ("startup", KazooState.CONNECTED),
            (KazooState.CONNECTED, KazooState.CONNECTED),
            (KazooState.CONNECTED, KazooState.SUSPENDED),
            (KazooState.CONNECTED, KazooState.LOST),
            (KazooState.SUSPENDED, KazooState.CONNECTED),
            (KazooState.SUSPENDED, KazooState.LOST),
            (KazooState.LOST, KazooState.CONNECTED),
        )
        for old_state, new_state, in test_inputs:
            yield self._check, old_state, new_state


class TestZookeeperStateConnected(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper._state_connected
    """
    def _setup(self):
        inst = self._init_basic_setup()
        inst.kazoo = MagicMock(spec_set=["client_id"])
        inst.kazoo.client_id = MagicMock(spec_set=["__getitem__"])
        inst.ensure_path = create_mock()
        inst.prefix = "/prefix"
        inst._parties = {
            "/patha": create_mock(["autojoin"]),
            "/pathb": create_mock(["autojoin"]),
        }
        inst._connected = create_mock(["set"])
        inst._on_connect = None
        return inst

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_basic(self, init):
        inst = self._setup()
        # Call
        inst._state_connected()
        # Tests
        inst.ensure_path.assert_called_once_with(inst.prefix, abs=True)
        inst._parties["/patha"].autojoin.assert_called_once_with()
        inst._parties["/pathb"].autojoin.assert_called_once_with()
        inst._connected.set.assert_called_once_with()

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_connloss(self, init):
        inst = self._setup()
        inst.ensure_path.side_effect = ZkNoConnection
        # Call
        inst._state_connected()
        # Tests
        ntools.assert_false(inst._connected.called)

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_on_connect(self, init):
        inst = self._setup()
        inst._on_connect = create_mock()
        # Call
        inst._state_connected()
        # Tests
        inst._on_connect.assert_called_once_with()

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_conn_flap(self, init):
        inst = self._setup()
        inst.kazoo.client_id = None
        # Call
        inst._state_connected()
        # Tests
        ntools.assert_false(inst.ensure_path.called)


class TestZookeeperStateDisconnected(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper._state_suspended AND
    lib.zk.zk.Zookeeper._state_lost

    _state_suspended and _state_lost currently have almost identical code, so
    test them both in the same way.
    """
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def _check(self, f_name, init, test_callback=False):
        inst = self._init_basic_setup()
        inst._connected = create_mock(["clear"])
        inst._on_disconnect = None
        if test_callback:
            inst._on_disconnect = create_mock()
        # Call
        getattr(inst, f_name)()
        # Tests
        inst._connected.clear.assert_called_once_with()
        if test_callback:
            inst._on_disconnect.assert_called_once_with()

    def test(self):
        """
        Test with and without a callback function defined
        """
        for f in "_state_suspended", "_state_lost":
            yield self._check, f, True
            yield self._check, f


class TestZookeeperIsConnected(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper.is_connected
    """
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def _check(self, connected, init):
        inst = self._init_basic_setup()
        inst._connected = create_mock(["is_set"])
        inst._connected.is_set.return_value = connected
        # Call
        ntools.eq_(inst.is_connected(), connected)
        # Tests
        inst._connected.is_set.assert_called_once_with()

    def test(self):
        for connected in True, False:
            yield self._check, connected


class TestZookeeperWaitConnected(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper.wait_connected
    """
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_connected(self, init):
        inst = self._init_basic_setup()
        inst.is_connected = create_mock()
        # Call
        inst.wait_connected()
        # Tests
        inst.is_connected.assert_called_once_with()

    @patch("lib.zk.zk.time.time", autospec=True)
    @patch("lib.zk.zk.logging.debug", autospec=True)
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_no_timeout(self, init, _, time_):
        inst = self._init_basic_setup()
        inst.is_connected = create_mock()
        inst.is_connected.return_value = False
        time_.side_effect = [0, 10, 20]
        inst._connected = create_mock(["wait"])
        inst._connected.wait.side_effect = [False, True]
        # Call
        inst.wait_connected(timeout=None)
        # Tests
        inst._connected.wait.assert_has_calls([call(timeout=10.0)] * 2)
        ntools.eq_(inst._connected.wait.call_count, 2)

    @patch("lib.zk.zk.time.time", autospec=True)
    @patch("lib.zk.zk.logging.debug", autospec=True)
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_timeout_success(self, init, _, time_):
        inst = self._init_basic_setup()
        inst.is_connected = create_mock()
        inst.is_connected.return_value = False
        time_.side_effect = [0, 10, 20]
        inst._connected = create_mock(["wait"])
        inst._connected.wait.side_effect = [False, True]
        # Call
        inst.wait_connected(timeout=15)
        # Tests
        inst._connected.wait.assert_has_calls([call(timeout=10.0),
                                               call(timeout=5.0)])
        ntools.eq_(inst._connected.wait.call_count, 2)

    @patch("lib.zk.zk.time.time", autospec=True)
    @patch("lib.zk.zk.logging.debug", autospec=True)
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_timeout_fail(self, init, _, time_):
        inst = self._init_basic_setup()
        inst.is_connected = create_mock()
        inst.is_connected.return_value = False
        time_.side_effect = [0, 10, 20]
        inst._connected = create_mock(["wait"])
        inst._connected.wait.side_effect = [False, False]
        # Call
        ntools.assert_raises(ZkNoConnection, inst.wait_connected, timeout=15)
        # Tests
        ntools.eq_(inst._connected.wait.call_count, 2)


class TestZookeeperEnsurePath(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper.ensure_path
    """
    def _setup(self):
        inst = self._init_basic_setup()
        inst.prefix = "/prefix"
        inst.kazoo = create_mock(["ensure_path"])
        return inst

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_basic(self, init):
        # Setup
        inst = self._setup()
        # Call
        inst.ensure_path("pathness")
        # Tests
        inst.kazoo.ensure_path.assert_called_once_with("/prefix/pathness")

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_abs(self, init):
        # Setup
        inst = self._setup()
        # Call
        inst.ensure_path("/path/to/stuff", abs=True)
        # Tests
        inst.kazoo.ensure_path.assert_called_once_with("/path/to/stuff")

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def _check_error(self, excp, init):
        # Setup
        inst = self._setup()
        inst.kazoo.ensure_path.side_effect = excp
        # Call
        ntools.assert_raises(ZkNoConnection, inst.ensure_path, "asdwaf")

    def test_errors(self):
        for excp in ConnectionLoss, SessionExpiredError:
            yield self._check_error, excp


class TestZookeeperPartySetup(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper.party_setup
    """
    def _setup(self, connected=True):
        inst = self._init_basic_setup()
        inst.is_connected = create_mock()
        inst.is_connected.return_value = connected
        inst.prefix = "/prefix"
        inst.kazoo = create_mock()
        inst.ensure_path = create_mock()
        inst._srv_id = "srvid"
        inst._parties = {}
        return inst

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_not_connected(self, init):
        inst = self._setup(connected=False)
        # Call
        ntools.assert_raises(ZkNoConnection, inst.party_setup)
        # Tests
        inst.is_connected.assert_called_once_with()

    @patch("lib.zk.zk.ZkParty", autospec=True)
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_basic(self, init, zkparty):
        inst = self._setup()
        # Call
        inst.party_setup()
        # Tests
        inst.ensure_path.assert_called_once_with("/prefix/party", abs=True)
        zkparty.assert_called_once_with(inst.kazoo, "/prefix/party",
                                        inst._srv_id, True)
        ntools.eq_(inst._parties, {"/prefix/party": zkparty.return_value})

    @patch("lib.zk.zk.ZkParty", autospec=True)
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_full(self, init, zkparty):
        inst = self._setup()
        # Call
        inst.party_setup("/pref", False)
        # Tests
        zkparty.assert_called_once_with(inst.kazoo, "/pref/party", inst._srv_id,
                                        False)


class TestZookeeperGetLock(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper.get_lock
    """
    def _setup(self, have_lock):
        inst = self._init_basic_setup()
        inst._zk_lock = create_mock(["acquire"])
        inst.kazoo = create_mock(["Lock"])
        inst.have_lock = create_mock()
        inst.have_lock.side_effect = have_lock
        inst.wait_connected = create_mock()
        inst._lock_epoch = 0
        inst.conn_epoch = 42
        inst._lock = create_mock(["set"])
        return inst

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_full(self, init):
        inst = self._setup((True,))
        inst._zk_lock = None
        inst.prefix = "/prefix"
        inst._srv_id = "srvid"
        lock = create_mock(["acquire"])
        lock.return_value = True
        inst.kazoo.Lock.return_value = lock
        # Call
        ntools.assert_true(inst.get_lock(lock_timeout="lock t/o",
                                         conn_timeout="conn t/o"))
        # Tests
        inst.kazoo.Lock.assert_called_once_with("/prefix/lock", "srvid")
        inst.wait_connected.assert_called_once_with(timeout="conn t/o")
        ntools.eq_(inst._lock_epoch, inst.conn_epoch)
        inst._zk_lock.acquire.assert_called_once_with(timeout="lock t/o")
        inst._lock.set.assert_called_once_with()

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_have_lock(self, init):
        inst = self._setup((True,))
        # Call
        ntools.assert_true(inst.get_lock())
        # Tests
        inst.have_lock.assert_called_once_with()

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_acquire_fail(self, init):
        inst = self._setup((False, False))
        inst._zk_lock.acquire.return_value = False
        # Call
        ntools.assert_false(inst.get_lock())
        # Tests
        inst.wait_connected.assert_called_once_with(timeout=None)
        inst._zk_lock.acquire.assert_called_once_with(timeout=None)
        ntools.assert_false(inst._lock.set.called)

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_acquire_timeout(self, init):
        inst = self._setup((False, False))
        inst._zk_lock.acquire.side_effect = LockTimeout
        # Call
        ntools.eq_(inst.get_lock(), False)
        # Tests
        ntools.assert_false(inst._lock.set.called)

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def _check_exception(self, excp, init):
        inst = self._setup((False,))
        inst._zk_lock.acquire.side_effect = excp
        # Call
        ntools.assert_raises(ZkNoConnection, inst.get_lock)

    def test_exceptions(self):
        for excp in (ConnectionLoss, SessionExpiredError):
            yield self._check_exception, excp


class TestZookeeperReleaseLock(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper.release_lock
    """
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_no_lock(self, init):
        inst = self._init_basic_setup()
        inst._lock = create_mock(["clear"])
        inst._zk_lock = None
        inst.is_connected = create_mock()
        # Call
        inst.release_lock()
        # Tests
        inst._lock.clear.assert_called_once_with()
        ntools.assert_false(inst.is_connected.called)

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_not_connected(self, init):
        inst = self._init_basic_setup()
        inst._lock = create_mock(["clear"])
        inst.is_connected = create_mock()
        inst.is_connected.return_value = False
        inst._zk_lock = create_mock(["is_acquired"])
        inst._zk_lock.is_acquired = True
        # Call
        inst.release_lock()
        # Tests
        inst._lock.clear.assert_called_once_with()
        inst.is_connected.assert_called_once_with()
        ntools.assert_false(inst._zk_lock.is_acquired)

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_release(self, init):
        inst = self._init_basic_setup()
        inst._lock = create_mock(["clear"])
        inst.is_connected = create_mock()
        inst._zk_lock = create_mock(["is_acquired", "release"])
        # Call
        inst.release_lock()
        # Tests
        inst._zk_lock.release.assert_called_once_with()

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def _check_exception(self, exception, init):
        inst = self._init_basic_setup()
        inst._lock = create_mock(["clear"])
        inst.is_connected = create_mock()
        inst._zk_lock = create_mock(["is_acquired", "release"])
        inst._zk_lock.release.side_effect = exception
        inst._zk_lock.is_acquired = True
        # Call
        inst.release_lock()
        # Tests
        ntools.assert_false(inst._zk_lock.is_acquired)

    def test_exceptions(self):
        for excp in (NoNodeError, ConnectionLoss,
                     SessionExpiredError):
            yield self._check_exception, excp


class TestZookeeperHaveLock(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper.have_lock
    """
    def _setup(self, connected, l_epoch, c_epoch, lock_is_set):
        inst = self._init_basic_setup()
        inst.is_connected = create_mock()
        inst.is_connected.return_value = connected
        inst._lock_epoch = l_epoch
        inst.conn_epoch = c_epoch
        inst._lock = create_mock(["is_set"])
        inst._lock.is_set.return_value = lock_is_set
        inst.release_lock = create_mock()
        return inst

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_have(self, init):
        inst = self._setup(True, 1, 1, True)
        # Call
        ntools.ok_(inst.have_lock())
        # Tests
        inst.is_connected.assert_called_once_with()
        inst._lock.is_set.assert_called_once_with()
        ntools.assert_false(inst.release_lock.called)

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def _check_not_have(self, connected, l_epoch, c_epoch, lock_is_set, init):
        inst = self._setup(connected, l_epoch, c_epoch, lock_is_set)
        # Call
        ntools.assert_false(inst.have_lock())
        # Tests
        inst.release_lock.assert_called_once_with()

    def test_not_have(self):
        for connected, l_epoch, c_epoch, lock_is_set in (
                (False, 1, 1, True),
                (True, 0, 1, True),
                (True, 1, 1, False),
        ):
            yield self._check_not_have, connected, l_epoch, c_epoch, lock_is_set


class TestZookeeperWaitLock(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper.wait_lock
    """
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test(self, init):
        inst = self._init_basic_setup()
        inst._lock = create_mock(["wait"])
        # Call
        inst.wait_lock()
        # Tests
        inst._lock.wait.assert_called_once_with()


class TestZookeeperGetLockHolder(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper.get_lock_holder
    """
    def _setup(self, contenders):
        inst = self._init_basic_setup()
        inst._zk_lock = create_mock(['contenders'])
        inst._zk_lock.contenders.return_value = contenders
        return inst

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_without_contenders(self, init):
        inst = self._setup([])
        # Call
        ntools.eq_(inst.get_lock_holder(), None)
        # Tests
        inst._zk_lock.contenders.assert_called_once_with()

    @patch("lib.zk.zk.ZkID.from_raw", autospec=True)
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_with_contenders(self, init, zkid):
        inst = self._setup([b"c3J2aWQx=", b"c3J2aWQy"])
        zkid.side_effect = lambda x: x
        # Call
        ntools.eq_(inst.get_lock_holder(), b"srvid1")

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def _check_error(self, excp, init):
        # Setup
        inst = self._setup([])
        inst._zk_lock.contenders.side_effect = excp
        # Call
        ntools.assert_raises(ZkNoConnection, inst.get_lock_holder)

    def test_errors(self):
        for excp in ConnectionLoss, SessionExpiredError:
            yield self._check_error, excp


class TestZookeeperRetry(BaseZookeeper):
    """
    Unit tests for lib.zk.zk.Zookeeper.retry
    """
    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_basic(self, init):
        inst = self._init_basic_setup()
        inst.wait_connected = create_mock()
        f = create_mock()
        # Call
        ntools.eq_(inst.retry("desc", f, "arg1", _timeout=5.4, kwarg1="k"),
                   f.return_value)
        # Tests
        inst.wait_connected.assert_called_once_with(timeout=5.4)
        f.assert_called_once_with("arg1", kwarg1="k")

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_no_conn(self, init):
        inst = self._init_basic_setup()
        inst.wait_connected = create_mock()
        inst.wait_connected.side_effect = ZkNoConnection
        f = create_mock()
        # Call
        ntools.assert_raises(ZkRetryLimit, inst.retry, "desc", f)
        # Tests
        inst.wait_connected.assert_has_calls([call(timeout=10.0)] * 5)
        ntools.eq_(inst.wait_connected.call_count, 5)
        ntools.assert_false(f.called)

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_no_retries(self, init):
        inst = self._init_basic_setup()
        inst.wait_connected = create_mock()
        inst.wait_connected.side_effect = ZkNoConnection
        # Call
        ntools.assert_raises(ZkRetryLimit, inst.retry, "desc", "f",
                             _retries=0)
        # Tests
        inst.wait_connected.assert_called_once_with(timeout=10.0)

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_inf_retries(self, init):
        inst = self._init_basic_setup()
        inst.wait_connected = create_mock()
        inst.wait_connected.side_effect = [ZkNoConnection] * 20
        f = create_mock()
        # Call
        ntools.assert_raises(StopIteration, inst.retry, "desc", f,
                             _retries=None)
        # Tests
        inst.wait_connected.assert_has_calls([call(timeout=10.0)] * 21)
        ntools.eq_(inst.wait_connected.call_count, 21)

    @patch("lib.zk.zk.Zookeeper.__init__", autospec=True, return_value=None)
    def test_conn_drop(self, init):
        inst = self._init_basic_setup()
        inst.wait_connected = create_mock()
        inst.wait_connected.return_value = True
        f = create_mock()
        f.side_effect = [ZkNoConnection, "success"]
        # Call
        ntools.eq_(inst.retry("desc", f), "success")
        # Tests
        inst.wait_connected.assert_has_calls([call(timeout=10.0)] * 2)
        ntools.eq_(inst.wait_connected.call_count, 2)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
