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
:mod:`lib_socket_test` --- lib.socket unit tests
================================================
"""
# Stdlib
import socket
from unittest.mock import patch

# External
import nose
from nose import tools as ntools

# SCION
from lib.defines import SCION_BUFLEN
from lib.socket import (
    UDPSocket,
    UDPSocketMgr,
)
from lib.types import AddrType
from test.testcommon import SCIONTestError, create_mock


class TestUDPSocketInit(object):
    """
    Unit tests for lib.socket.UDPSocket.__init__
    """
    @patch("lib.socket.UDPSocket.bind", autospec=True)
    @patch("lib.socket.socket", autospec=True)
    def test_full(self, socket_, bind):
        socket_.return_value = create_mock(["setsockopt"])
        # Call
        inst = UDPSocket(bind=("addr", "port"), addr_type=AddrType.IPV4)
        # Tests
        ntools.eq_(inst._addr_type, AddrType.IPV4)
        socket_.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        ntools.assert_is_none(inst.port)
        bind.assert_called_once_with(inst, "addr", "port")

    @patch("lib.socket.UDPSocket.bind", autospec=True)
    @patch("lib.socket.socket", autospec=True)
    def test_minimal(self, socket_, bind):
        socket.return_value = create_mock(["setsockopt"])
        # Call
        UDPSocket()
        # Tests
        socket_.assert_called_once_with(socket.AF_INET6, socket.SOCK_DGRAM)
        ntools.assert_false(bind.called)


class TestUDPSocketBind(object):
    """
    Unit tests for lib.socket.UDPSocket.bind
    """
    def _setup(self):
        inst = UDPSocket()
        inst.sock = create_mock(["bind", "getsockname"])
        inst.sock.getsockname.return_value = ["addr", 5353]
        return inst

    @patch("lib.socket.UDPSocket.__init__", autospec=True, return_value=None)
    def test_addr(self, init):
        inst = self._setup()
        # Call
        inst.bind("addr", 4242, desc="Testing")
        # Tests
        inst.sock.bind.assert_called_once_with(("addr", 4242))
        ntools.eq_(inst.port, 5353)

    @patch("lib.socket.UDPSocket.__init__", autospec=True, return_value=None)
    def test_any_v4(self, init):
        inst = self._setup()
        inst._addr_type = AddrType.IPV4
        # Call
        inst.bind(None, 4242)
        # Tests
        inst.sock.bind.assert_called_once_with(("", 4242))

    @patch("lib.socket.UDPSocket.__init__", autospec=True, return_value=None)
    def test_any_v6(self, init):
        inst = self._setup()
        inst._addr_type = AddrType.IPV6
        # Call
        inst.bind(None, 4242)
        # Tests
        inst.sock.bind.assert_called_once_with(("::", 4242))

    @patch("lib.socket.kill_self", autospec=True)
    @patch("lib.socket.UDPSocket.__init__", autospec=True, return_value=None)
    def test_error(self, init, kill_self):
        inst = self._setup()
        inst.sock.bind.side_effect = OSError
        kill_self.side_effect = SCIONTestError
        # Call
        ntools.assert_raises(SCIONTestError, inst.bind, "a", "b")
        # Tests
        kill_self.assert_called_once_with()


class TestUDPSocketSend(object):
    """
    Unit tests for lib.socket.UDPSocket.send
    """
    @patch("lib.socket.UDPSocket.__init__", autospec=True, return_value=None)
    def test_basic(self, init):
        inst = UDPSocket()
        inst.sock = create_mock(["sendto"])
        # Call
        inst.send("data", "dst")
        # Tests
        inst.sock.sendto.assert_called_once_with("data", "dst")

    @patch("lib.socket.logging.error", autospec=True)
    @patch("lib.socket.UDPSocket.__init__", autospec=True, return_value=None)
    def test_error(self, init, logging):
        inst = UDPSocket()
        inst.sock = create_mock(["sendto"])
        inst.sock.sendto.side_effect = OSError
        # Call
        inst.send("data", "dst")
        # Tests
        ntools.ok_(logging.called)


class TestUDPSocketRecv(object):
    """
    Unit tests for lib.socket.UDPSocket.recv
    """
    @patch("lib.socket.UDPSocket.__init__", autospec=True, return_value=None)
    def test_block(self, init):
        inst = UDPSocket()
        inst.sock = create_mock(["recvfrom"])
        # Call
        ntools.eq_(inst.recv(), inst.sock.recvfrom.return_value)
        # Tests
        inst.sock.recvfrom.assert_called_once_with(SCION_BUFLEN, 0)

    @patch("lib.socket.UDPSocket.__init__", autospec=True, return_value=None)
    def test_nonblock(self, init):
        inst = UDPSocket()
        inst.sock = create_mock(["recvfrom"])
        # Call
        inst.recv(block=False)
        # Tests
        inst.sock.recvfrom.assert_called_once_with(SCION_BUFLEN,
                                                   socket.MSG_DONTWAIT)

    @patch("lib.socket.UDPSocket.__init__", autospec=True, return_value=None)
    def test_intr(self, init):
        inst = UDPSocket()
        inst.sock = create_mock(["recvfrom"])
        inst.sock.recvfrom.side_effect = (
            InterruptedError, InterruptedError, "data")
        # Call
        ntools.eq_(inst.recv(), "data")
        # Tests
        ntools.eq_(inst.sock.recvfrom.call_count, 3)


class TestUDPSocketMgrSelect(object):
    """
    Unit tests for lib.socket.UDPSocketMgr.select
    """
    @patch("lib.socket.UDPSocketMgr.__init__", autospec=True, return_value=None)
    def test(self, init):
        inst = UDPSocketMgr()
        inst._sel = create_mock(["select"])
        events = []
        for i in range(3):
            key = create_mock(["data"])
            key.data = "sock%d" % i
            events.append((key, None))
        inst._sel.select.return_value = events
        # Call
        ntools.eq_(inst.select_(timeout="timeout"), ["sock0", "sock1", "sock2"])
        # Tests
        inst._sel.select.assert_called_once_with(timeout="timeout")


class TestUDPSocketMgrClose(object):
    """
    Unit tests for lib.socket.UDPSocketMgr.close
    """
    @patch("lib.socket.UDPSocketMgr.__init__", autospec=True, return_value=None)
    def test(self, init):
        inst = UDPSocketMgr()
        inst._sel = create_mock(["close", "get_map"])
        inst.remove = create_mock()
        map_ = {}
        for i in range(3):
            entry = create_mock(["data"])
            entry.data = create_mock(["close"])
            map_[i] = entry
        inst._sel.get_map.return_value = map_
        # Call
        inst.close()
        # Tests
        inst._sel.get_map.assert_called_once_with()
        for entry in map_.values():
            inst.remove.assert_any_call(entry.data)
            entry.data.close.assert_called_once_with()
        ntools.eq_(inst.remove.call_count, 3)
        inst._sel.close.assert_called_once_with()


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
