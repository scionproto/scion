# Copyright 2015 ETH Zurich
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
:mod:`cache_test` --- lib.zk.cache unit tests
======================================================
"""
# Stdlib
from unittest.mock import call, patch

# External packages
import nose
import nose.tools as ntools
from kazoo.exceptions import (
    ConnectionLoss,
    NoNodeError,
    NodeExistsError,
    SessionExpiredError,
)

# SCION
from lib.zk.errors import ZkNoConnection, ZkNoNodeError
from lib.zk.cache import ZkSharedCache
from test.testcommon import assert_these_calls, create_mock


class TestZkSharedCacheStore(object):
    """
    Unit tests for lib.zk.cache.ZkSharedCache.store
    """
    def _setup(self):
        inst = ZkSharedCache("zk", "path", "handler")
        inst._path = "/path"
        inst._zk = create_mock(["is_connected"])
        inst._kazoo = create_mock(["create", "set"])
        inst._incoming_entries = create_mock(["append"])
        return inst

    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def test_not_connected(self, init):
        inst = self._setup()
        inst._zk.is_connected.return_value = False
        # Call
        ntools.assert_raises(ZkNoConnection, inst.store, 'n', 'v')
        # Tests
        inst._zk.is_connected.assert_called_once_with()

    @patch("lib.zk.cache.time.time", autospec=True)
    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def test_set(self, init, time_):
        inst = self._setup()
        # Call
        inst.store('n', 'v')
        # Tests
        inst._kazoo.set.assert_called_once_with("/path/n", "v")
        ntools.assert_false(inst._kazoo.create.called)
        inst._incoming_entries.append.assert_called_once_with(
            ("n", time_.return_value))

    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def _check_set_conn_loss(self, excp, init):
        inst = self._setup()
        inst._kazoo.set.side_effect = excp
        # Call
        ntools.assert_raises(ZkNoConnection, inst.store, 'n', 'v')

    def test_set_conn_loss(self):
        for excp in ConnectionLoss, SessionExpiredError:
            yield self._check_set_conn_loss, excp

    @patch("lib.zk.cache.time.time", autospec=True)
    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def test_create(self, init, time_):
        inst = self._setup()
        inst._kazoo.set.side_effect = NoNodeError
        # Call
        inst.store('n', 'v')
        # Tests
        inst._kazoo.create.assert_called_once_with("/path/n", "v",
                                                   makepath=True)
        inst._incoming_entries.append.assert_called_once_with(
            ("n", time_.return_value))

    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def test_suddenly_exists(self, init):
        inst = self._setup()
        inst._kazoo.set.side_effect = NoNodeError
        inst._kazoo.create.side_effect = NodeExistsError
        # Call
        inst.store('n', 'v')

    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def _check_create_conn_loss(self, excp, init):
        inst = self._setup()
        inst._kazoo.set.side_effect = NoNodeError
        inst._kazoo.create.side_effect = excp
        # Call
        ntools.assert_raises(ZkNoConnection, inst.store, 'n', 'v')

    def test_create_conn_loss(self):
        for excp in ConnectionLoss, SessionExpiredError:
            yield self._check_create_conn_loss, excp


class TestZkSharedCacheProcess(object):
    """
    Unit tests for lib.zk.cache.ZkSharedCache.process
    """
    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def test_not_connected(self, init):
        inst = ZkSharedCache("zk", "path", "handler")
        inst._zk = create_mock(["is_connected"])
        inst._zk.is_connected.return_value = False
        # Call
        ntools.assert_raises(ZkNoConnection, inst.process)
        # Tests
        inst._zk.is_connected.assert_called_once_with()

    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def test_full(self, init):
        inst = ZkSharedCache("zk", "path", "handler")
        inst._zk = create_mock(["conn_epoch", "is_connected"])
        inst._incoming_entries = create_mock(["__bool__", "popleft"])
        inst._incoming_entries.__bool__.side_effect = True, True, False
        inst._incoming_entries.popleft.side_effect = ("inc0", 1), ("inc1", 0)
        inst._entries = {"inc0": 0, "old0": 0}
        inst._list_entries = create_mock()
        inst._list_entries.return_value = "inc0", "inc1", "new0"
        inst._handle_entries = create_mock()
        inst._path = "/path"
        # Call
        inst.process()
        # Tests
        ntools.eq_(inst._entries, {"inc0": 0, "inc1": 0})
        inst._handle_entries.assert_called_once_with({"new0"})


class TestZkSharedCacheGet(object):
    """
    Unit tests for lib.zk.cache.ZkSharedCache._get
    """
    @patch("lib.zk.cache.time.time", autospec=True)
    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def test_success(self, init, time_):
        inst = ZkSharedCache("zk", "path", "handler")
        inst._path = "/path"
        inst._kazoo = create_mock(["get"])
        inst._kazoo.get.return_value = ("data", "meta")
        inst._entries = create_mock(["setdefault"])
        # Call
        ntools.eq_(inst._get("name"), "data")
        # Tests
        inst._kazoo.get.assert_called_once_with("/path/name")
        inst._entries.setdefault.assert_called_once_with(
            "name", time_.return_value)

    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def test_no_entry(self, init):
        inst = ZkSharedCache("zk", "path", "handler")
        inst._path = "/path"
        inst._kazoo = create_mock(["get"])
        inst._kazoo.get.side_effect = NoNodeError
        inst._entries = create_mock(["pop"])
        # Call
        ntools.assert_raises(ZkNoNodeError, inst._get, "name")
        # Tests
        inst._kazoo.get.assert_called_once_with("/path/name")
        inst._entries.pop.assert_called_once_with("name", None)

    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def _check_exception(self, excp, expected, init):
        inst = ZkSharedCache("zk", "path", "handler")
        inst._path = "/path"
        inst._kazoo = create_mock(["get"])
        inst._kazoo.get.side_effect = excp
        # Call
        ntools.assert_raises(expected, inst._get, "name")

    def test_exceptions(self):
        for excp, expected in (
            (ConnectionLoss, ZkNoConnection),
            (SessionExpiredError, ZkNoConnection),
        ):
            yield self._check_exception, excp, expected


class TestZkSharedCacheListEntries(object):
    """
    Unit tests for lib.zk.cache.ZkSharedCache._list_entries
    """
    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def test_sucesss(self, init):
        inst = ZkSharedCache("zk", "path", "handler")
        inst._path = "/path"
        inst._kazoo = create_mock(["get_children"])
        inst._kazoo.get_children.return_value = [
            "node0", "node1", "node2", "node3"]
        # Call
        ntools.eq_(inst._list_entries(),
                   {"node0", "node1", "node2", "node3"})

    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def test_no_cache(self, init):
        inst = ZkSharedCache("zk", "path", "handler")
        inst._path = "/path"
        inst._kazoo = create_mock(["get_children"])
        inst._kazoo.get_children.side_effect = NoNodeError
        # Call
        ntools.eq_(inst._list_entries(), set())

    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def _check_children_exception(self, excp, expected, init):
        inst = ZkSharedCache("zk", "path", "handler")
        inst._path = "/path"
        inst._kazoo = create_mock(["get_children"])
        inst._kazoo.get_children.side_effect = excp
        # Call
        ntools.assert_raises(expected, inst._list_entries)

    def test_children_exceptions(self):
        for excp, expected in (
            (ConnectionLoss, ZkNoConnection),
            (SessionExpiredError, ZkNoConnection),
        ):
            yield self._check_children_exception, excp, expected


class TestZkSharedCacheHandleEntries(object):
    """
    Unit test for lib.zk.cache.ZkSharedCache._handle_entries
    """
    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = ZkSharedCache("zk", "path", "handler")
        entry_names = ["entry0", "entry1", "entry2", "entry3"]
        inst._get = create_mock()
        inst._get.side_effect = [
            "data0", ZkNoNodeError, "data2", ZkNoConnection
        ]
        inst._path = "/path"
        inst._handler = create_mock()
        # Call
        ntools.eq_(inst._handle_entries(entry_names), 2)
        # Tests
        assert_these_calls(inst._get, ([call(i) for i in entry_names]))
        inst._handler.assert_called_once_with(["data0", "data2"])


class TestZkSharedCacheExpire(object):
    """
    Unit test for lib.zk.cache.ZkSharedCache.expire
    """
    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def test_not_connected(self, init):
        inst = ZkSharedCache("zk", "path", "handler")
        inst._zk = create_mock(["is_connected"])
        inst._zk.is_connected.return_value = False
        # Call
        ntools.assert_raises(ZkNoConnection, inst.expire, 42)
        # Tests
        inst._zk.is_connected.assert_called_once_with()

    def _setup(self, time_, entries):
        inst = ZkSharedCache("zk", "path", "handler")
        inst._zk = create_mock(["is_connected"])
        time_.return_value = 1000
        inst._entries = entries
        inst._kazoo = create_mock(["delete"])
        inst._path = "/path"
        return inst

    @patch("lib.zk.cache.time.time", autospec=True)
    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def test_success(self, init, time_):
        entries = {}
        for last_seen in 1000, 999, 996, 995, 994, 990, 1001:
            entries["entry%d" % last_seen] = last_seen
        inst = self._setup(time_, entries)
        # Call
        inst.expire(5)
        # Tests
        assert_these_calls(inst._kazoo.delete, [
            call("/path/entry994"), call("/path/entry990")
        ], any_order=True)

    @patch("lib.zk.cache.time.time", autospec=True)
    @patch("lib.zk.cache.ZkSharedCache.__init__", autospec=True,
           return_value=None)
    def _check_exception(self, excp, expected, init, time_):
        inst = self._setup(time_, {"entry1": 0})
        inst._kazoo.delete.side_effect = excp
        # Call
        ntools.assert_raises(expected, inst.expire, 5)

    def test_exceptions(self):
        for excp, expected in (
            (NoNodeError, ZkNoNodeError),
            (ConnectionLoss, ZkNoConnection),
            (SessionExpiredError, ZkNoConnection),
        ):
            yield self._check_exception, excp, expected


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
