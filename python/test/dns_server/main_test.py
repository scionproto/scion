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
:mod:`main_test` --- dns_server.main unit tests
==============================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools
from dnslib import DNSLabel

# SCION
from dns_server.main import SCIONDnsServer
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    DNS_SERVICE,
    PATH_SERVICE,
    SCION_DNS_PORT,
    SIBRA_SERVICE,
)
from lib.zk.errors import ZkNoConnection
from test.testcommon import create_mock


class BaseDNSServer(object):
    DOMAIN = DNSLabel("testdomainpleaseignore")
    NAME = "notaninstance"
    FQDN = DOMAIN.add(NAME)


class TestSCIONDnsServerSetup(BaseDNSServer):
    """
    Unit tests for dns_server.main.SCIONDnsServer.setup
    """
    @patch("dns_server.main.Zookeeper", autospec=True)
    @patch("dns_server.main.SCIONDnsLogger", autospec=True)
    @patch("dns_server.main.SCIONDnsTcpServer", autospec=True)
    @patch("dns_server.main.SCIONDnsUdpServer", autospec=True)
    @patch("dns_server.main.DNSServer", autospec=True)
    @patch("dns_server.main.ZoneResolver", autospec=True)
    @patch("dns_server.main.SCIONDnsServer.__init__",
           autospec=True, return_value=None)
    def test(self, init, zone_resolver, dns_server, udp_server, tcp_server,
             dns_logger, zookeeper):
        # Setup
        server = SCIONDnsServer("srvid", "conf_dir")
        server.lock = "lock"
        server.domain = "domain"
        server.addr = create_mock(["host"])
        server.addr.host = "127.0.0.1"
        server.id = "srvid"
        server.topology = create_mock(["isd_as", "zookeepers"])
        server.topology.isd_as = "isd as"
        server.topology.zookeepers = ["zk0", "zk1"]
        server._setup_parties = create_mock()
        # Call
        server.setup()
        # Tests
        zone_resolver.assert_called_once_with("lock", "domain")
        dns_server.assert_any_call(
            zone_resolver.return_value, port=SCION_DNS_PORT,
            address="127.0.0.1", server=udp_server,
            logger=dns_logger.return_value)
        dns_server.assert_any_call(
            zone_resolver.return_value, port=SCION_DNS_PORT,
            address="127.0.0.1", server=tcp_server,
            logger=dns_logger.return_value)
        ntools.eq_(dns_server.call_count, 2)
        zookeeper.assert_called_once_with(
            "isd as", DNS_SERVICE, "srvid\0%d\000127.0.0.1" % SCION_DNS_PORT,
            ["zk0", "zk1"])
        ntools.eq_(server._parties, {})
        server._setup_parties.assert_called_once_with()


class TestSCIONDnsSetupParties(BaseDNSServer):
    """
    Unit tests for dns_server.main.SCIONDnsServer._setup_parties
    """
    @patch("dns_server.main.SCIONDnsServer.__init__",
           autospec=True, return_value=None)
    def test(self, _):
        server = SCIONDnsServer("srvid", "conf_dir")
        server.zk = create_mock(["retry", "party_setup"])
        server.addr = create_mock(["isd_as"])
        server.addr.isd_as = "30-10"
        server._parties = {}
        # Call
        server._setup_parties()
        # Tests
        for srv in server.SRV_TYPES:
            autojoin = False
            if srv == DNS_SERVICE:
                autojoin = True
            server.zk.retry.assert_any_call(
                "Joining %s party" % srv, server.zk.party_setup,
                prefix="/30-10/%s" % srv, autojoin=autojoin)
        ntools.eq_(server.zk.retry.call_count, len(server.SRV_TYPES))


class TestSCIONDnsSyncZkState(BaseDNSServer):
    """
    Unit tests for dns_server.main.SCIONDnsServer._sync_zk_state
    """
    @patch("dns_server.main.SCIONDnsServer.__init__",
           autospec=True, return_value=None)
    def test_success(self, init):
        # Setup
        services = {
            BEACON_SERVICE: ["bs1", "bs2", "bs3"],
            CERTIFICATE_SERVICE: ["cs1"],
            DNS_SERVICE: ["ds1", "ds2"],
            PATH_SERVICE: [],
            SIBRA_SERVICE: ["sb1"],
        }
        server = SCIONDnsServer("srvid", "conf_dir")
        server.zk = create_mock(['wait_connected'])
        server.domain = self.DOMAIN
        server._parties = {}
        for i in SCIONDnsServer.SRV_TYPES:
            party = create_mock(["list"])
            party.list.return_value = services[i]
            server._parties[i] = party
        server._parse_srv_inst = create_mock()
        server.lock = create_mock(['__enter__', '__exit__'])
        server.resolver = create_mock(["services"])
        domain_set = set([self.DOMAIN.add(srv) for srv in
                          SCIONDnsServer.SRV_TYPES])
        # Call
        server._sync_zk_state()
        # Tests
        server.zk.wait_connected.assert_called_once_with(timeout=10.0)
        ntools.eq_(domain_set, set(server.services))
        for type_, insts in services.items():
            for inst in insts:
                server._parse_srv_inst.assert_any_call(
                    inst, self.DOMAIN.add(type_))
        ntools.ok_(server.lock.mock_calls)
        ntools.eq_(server.resolver.services, server.services)

    @patch("dns_server.main.SCIONDnsServer.__init__",
           autospec=True, return_value=None)
    def test_no_conn(self, init):
        # Setup
        server = SCIONDnsServer("srvid", "conf_dir")
        server.zk = create_mock(['wait_connected'])
        server.zk.wait_connected.side_effect = ZkNoConnection
        # Call
        server._sync_zk_state()
        # Tests
        server.zk.wait_connected.assert_called_once_with(timeout=10.0)
        ntools.eq_(server.services, {})

    @patch("dns_server.main.SCIONDnsServer.__init__",
           autospec=True, return_value=None)
    def test_connloss(self, init):
        # Setup
        server = SCIONDnsServer("srvid", "conf_dir")
        server.zk = create_mock(['wait_connected'])
        server.domain = self.DOMAIN
        party = create_mock(["list"])
        party.list.side_effect = ZkNoConnection
        server._parties = {
            SCIONDnsServer.SRV_TYPES[0]: party
        }
        # Call
        server._sync_zk_state()


class TestSCIONDnsParseSrvInst(BaseDNSServer):
    """
    Unit tests for dns_server.main.SCIONDnsServer._parse_srv_inst
    """
    @patch("dns_server.main.SCIONDnsServer.__init__",
           autospec=True, return_value=None)
    def test(self, init):
        # Setup
        server = SCIONDnsServer("srvid", "conf_dir")
        srv_domain = self.DOMAIN.add(BEACON_SERVICE)
        server.services = {srv_domain: ["addr0"]}
        # Call
        server._parse_srv_inst("name\0port\0addr1\0addr2", srv_domain)
        # Tests
        ntools.eq_(server.services[srv_domain], ["addr0", "addr1", "addr2"])


class TestSCIONDnsRun(BaseDNSServer):
    """
    Unit tests for dns_server.main.SCIONDnsServer.run
    """
    @patch("dns_server.main.sleep")
    @patch("dns_server.main.SCIONDnsServer.__init__",
           autospec=True, return_value=None)
    def test(self, init, sleep):
        # Setup
        server = SCIONDnsServer("srvid", "conf_dir")
        server._sync_zk_state = create_mock()
        server.udp_server = create_mock(["start_thread", "isAlive"])
        server.tcp_server = create_mock(["start_thread", "isAlive"])
        sleep.side_effect = []
        # Call
        ntools.assert_raises(StopIteration, server.run)
        # Tests
        ntools.eq_(server._sync_zk_state.call_count, 2)
        server.udp_server.start_thread.assert_called_once_with()
        server.tcp_server.start_thread.assert_called_once_with()
        server.udp_server.isAlive.assert_called_once_with()
        server.tcp_server.isAlive.assert_called_once_with()
        sleep.assert_called_once_with(server.SYNC_TIME)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
