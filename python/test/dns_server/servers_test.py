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
:mod:`servers_test` --- dns_server.servers unit tests
====================================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from dns_server.servers import (
    SCIONDnsTcpServer,
    SCIONDnsUdpServer,
)
from test.testcommon import create_mock


class TestSCIONDnsProtocolServerServeForever(object):
    """
    Unit tests for:
        dns_server.servers.SCIONDnsTcpServer.serve_forever
        dns_server.servers.SCIONDnsUdpServer.serve_forever
    """
    @patch('dns_server.servers.threading.current_thread',
           autospec=True)
    def _check(self, inst, srv_forever, curr_thread):
        # Setup
        curr_thread.return_value = create_mock(["name"])
        # Call
        inst.serve_forever()
        # Tests
        ntools.assert_is_instance(curr_thread.return_value.name, str)
        srv_forever.assert_called_once_with(inst)

    @patch('dns_server.servers.TCPServer.serve_forever',
           autospec=True)
    @patch('dns_server.servers.SCIONDnsTcpServer.__init__',
           autospec=True, return_value=None)
    def test_tcp(self, _, srv_forever):
        self._check(SCIONDnsTcpServer("srvaddr", "reqhndlcls"), srv_forever)

    @patch('dns_server.servers.UDPServer.serve_forever',
           autospec=True)
    @patch('dns_server.servers.SCIONDnsUdpServer.__init__',
           autospec=True, return_value=None)
    def test_udp(self, _, srv_forever):
        self._check(SCIONDnsUdpServer("srvaddr", "reqhndlcls"), srv_forever)


class TestSCIONDnsProtocolServerHandleError(object):
    """
    Unit tests for:
        dns_server.servers.SCIONDnsTcpServer.handle_error
        dns_server.servers.SCIONDnsUdpServer.handle_error
    """
    @patch('dns_server.servers.kill_self', autospec=True)
    @patch('dns_server.servers.log_exception', autospec=True)
    def _check(self, inst, log_excp, kill_self):
        # Call
        inst.handle_error()
        # Tests
        ntools.ok_(log_excp.called)
        kill_self.assert_called_once_with()

    @patch('dns_server.servers.SCIONDnsTcpServer.__init__',
           autospec=True, return_value=None)
    def test_tcp(self, _):
        self._check(SCIONDnsTcpServer("srvaddr", "reqhndlcls"))

    @patch('dns_server.servers.SCIONDnsUdpServer.__init__',
           autospec=True, return_value=None)
    def test_udp(self, _):
        self._check(SCIONDnsUdpServer("srvaddr", "reqhndlcls"))


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
