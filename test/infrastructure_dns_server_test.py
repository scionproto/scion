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
:mod:`dns_server_test` --- infrastructure.dns_server unit tests
===============================================================
"""
# Stdlib
from unittest.mock import call, patch, create_autospec

# External packages
import nose
import nose.tools as ntools
from dnslib import DNSLabel, DNSRecord, QTYPE, RCODE

# SCION
from infrastructure.dns_server import (
    SCIONDnsServer,
    SCIONDnsUdpServer,
    SCIONDnsTcpServer,
    ZoneResolver,
)
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    DNS_SERVICE,
    PATH_SERVICE,
    SCION_DNS_PORT,
)
from lib.zookeeper import ZkConnectionLoss
from test.testcommon import create_mock


class BaseDNSServer(object):
    """
    Base class for infrastructure.dns_server tests
    """
    DOMAIN = DNSLabel("testdomainpleaseignore")
    NAME = "notaninstance"
    FQDN = DOMAIN.add(NAME)

    def _setup_zoneresolver(self):
        self.lock = create_mock(["__enter__", "__exit__"])
        return ZoneResolver(self.lock, self.DOMAIN)


class TestZoneResolverInit(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.ZoneResolver.__init__
    """
    def test(self):
        # Call
        inst = ZoneResolver("lock", "domain")
        # Tests
        ntools.eq_(inst.lock, "lock")
        ntools.eq_(inst.domain, "domain")
        ntools.eq_(inst.services, {})


class TestZoneResolverResolve(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.ZoneResolver.resolve
    """
    def test_forward(self):
        # Setup
        inst = self._setup_zoneresolver()
        inst.resolve_forward = create_mock()
        request = create_autospec(DNSRecord, spec_set=True)
        reply = request.reply.return_value = "2345as"
        qname = request.q.qname = DNSLabel("a.tiny.teacup")
        request.q.qtype = QTYPE.A
        # Call
        ntools.eq_(inst.resolve(request, None), reply)
        # Tests
        inst.resolve_forward.assert_called_once_with(qname, "A", reply)

    @patch("infrastructure.dns_server.logging.warning", autospec=True)
    def test_unsupported(self, warning):
        # Setup
        inst = self._setup_zoneresolver()
        inst.resolve_forward = create_mock()
        request = create_autospec(DNSRecord, spec_set=True)
        reply = request.reply.return_value = create_mock(["header"])
        reply.header = create_mock(["rcode"])
        request.q.qname = DNSLabel("a.tinier.teacup")
        request.q.qtype = QTYPE.MX
        # Call
        ntools.eq_(inst.resolve(request, None), reply)
        # Tests
        ntools.assert_false(inst.resolve_forward.called)
        ntools.assert_true(warning.called)
        ntools.eq_(reply.header.rcode, RCODE.NXDOMAIN)


class TestZoneResolverResolveForward(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.ZoneResolver.resolve_forward
    """
    @patch("infrastructure.dns_server.logging.warning", autospec=True)
    def test_outside_domain(self, warning):
        # Setup
        inst = self._setup_zoneresolver()
        reply = create_mock(["header"])
        reply.header = create_mock(["rcode"])
        # Call
        inst.resolve_forward(DNSLabel("anotherdomain"), "A", reply)
        # Tests
        ntools.ok_(warning.called)
        ntools.eq_(reply.header.rcode, RCODE.NOTAUTH)
        ntools.assert_false(self.lock.__enter__.called)

    @patch("infrastructure.dns_server.A", autospec=True)
    @patch("infrastructure.dns_server.RR", autospec=True)
    def test_service_alias(self, rr, a):
        # Setup
        inst = self._setup_zoneresolver()
        reply = create_mock(['add_answer'])
        srvalias = self.DOMAIN.add(BEACON_SERVICE)
        inst.services[srvalias] = "ip0", "ip1"
        a.side_effect = "a0", "a1"
        rr.side_effect = "rr0", "rr1"
        # Call
        inst.resolve_forward(srvalias, "A", reply)
        # Tests
        self.lock.__enter__.assert_called_once_with()
        a.assert_has_calls([call("ip0"), call("ip1")])
        rr.assert_has_calls([
            call(srvalias, QTYPE.A, rdata="a0"),
            call(srvalias, QTYPE.A, rdata="a1"),
        ])
        reply.add_answer.assert_has_calls([call("rr0"), call("rr1")])

    @patch("infrastructure.dns_server.logging.warning", autospec=True)
    def test_service_fail(self, warning):
        # Setup
        inst = self._setup_zoneresolver()
        reply = create_mock(["header"])
        reply.header = create_mock(["rcode"])
        srvalias = self.DOMAIN.add(BEACON_SERVICE)
        inst.services[srvalias] = []
        # Call
        inst.resolve_forward(srvalias, "A", reply)
        # Tests
        ntools.ok_(warning.called)
        ntools.eq_(reply.header.rcode, RCODE.SERVFAIL)

    @patch("infrastructure.dns_server.logging.warning", autospec=True)
    def test_unknown(self, warning):
        # Setup
        inst = self._setup_zoneresolver()
        reply = create_mock(["header"])
        reply.header = create_mock(["rcode"])
        # Call
        inst.resolve_forward(self.FQDN, "A", reply)
        # Tests
        ntools.ok_(warning.called)
        ntools.eq_(reply.header.rcode, RCODE.NXDOMAIN)


class TestSCIONDnsProtocolServerServeForever(object):
    """
    Unit tests for:
        infrastructure.dns_server.SCIONDnsTcpServer.serve_forever
        infrastructure.dns_server.SCIONDnsUdpServer.serve_forever
    """
    @patch('infrastructure.dns_server.threading.current_thread', autospec=True)
    def _check(self, inst, srv_forever, curr_thread):
        # Setup
        curr_thread.return_value = create_mock(["name"])
        # Call
        inst.serve_forever()
        # Tests
        ntools.assert_is_instance(curr_thread.return_value.name, str)
        srv_forever.assert_called_once_with(inst)

    @patch('infrastructure.dns_server.TCPServer.serve_forever', autospec=True)
    @patch('infrastructure.dns_server.SCIONDnsTcpServer.__init__',
           autospec=True, return_value=None)
    def test_tcp(self, _, srv_forever):
        self._check(SCIONDnsTcpServer("srvaddr", "reqhndlcls"), srv_forever)

    @patch('infrastructure.dns_server.UDPServer.serve_forever', autospec=True)
    @patch('infrastructure.dns_server.SCIONDnsUdpServer.__init__',
           autospec=True, return_value=None)
    def test_udp(self, _, srv_forever):
        self._check(SCIONDnsUdpServer("srvaddr", "reqhndlcls"), srv_forever)


class TestSCIONDnsProtocolServerHandleError(object):
    """
    Unit tests for:
        infrastructure.dns_server.SCIONDnsTcpServer.handle_error
        infrastructure.dns_server.SCIONDnsUdpServer.handle_error
    """
    @patch('infrastructure.dns_server.kill_self', autospec=True)
    @patch('infrastructure.dns_server.log_exception', autospec=True)
    def _check(self, inst, log_excp, kill_self):
        # Call
        inst.handle_error()
        # Tests
        ntools.ok_(log_excp.called)
        kill_self.assert_called_once_with()

    @patch('infrastructure.dns_server.SCIONDnsTcpServer.__init__',
           autospec=True, return_value=None)
    def test_tcp(self, _):
        self._check(SCIONDnsTcpServer("srvaddr", "reqhndlcls"))

    @patch('infrastructure.dns_server.SCIONDnsUdpServer.__init__',
           autospec=True, return_value=None)
    def test_udp(self, _):
        self._check(SCIONDnsUdpServer("srvaddr", "reqhndlcls"))


class TestSCIONDnsServerInit(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer.__init__
    """
    @patch('infrastructure.dns_server.threading.Lock', autospec=True)
    @patch('infrastructure.dns_server.SCIONElement.__init__', autospec=True,
           return_value=None)
    def test(self, elem_init, lock):
        # Call
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        # Tests
        elem_init.assert_called_once_with(server, DNS_SERVICE, "topofile",
                                          server_id="srvid")
        ntools.eq_(server.domain, self.DOMAIN)
        ntools.eq_(server.lock, lock.return_value)
        ntools.eq_(server.services, {})


class TestSCIONDnsServerSetup(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer.setup
    """
    @patch("infrastructure.dns_server.Zookeeper", autospec=True)
    @patch("infrastructure.dns_server.SCIONDnsLogger", autospec=True)
    @patch("infrastructure.dns_server.DNSServer", autospec=True)
    @patch("infrastructure.dns_server.ZoneResolver", autospec=True)
    @patch("infrastructure.dns_server.SCIONDnsServer.__init__", autospec=True,
           return_value=None)
    def test(self, init, zone_resolver, dns_server, dns_logger,
             zookeeper):
        # Setup
        server = SCIONDnsServer("srvid", "domain", "topofile")
        server.lock = "lock"
        server.domain = "domain"
        server.addr = create_mock(["host_addr"])
        server.addr.host_addr = "127.0.0.1"
        server.id = "srvid"
        server.topology = create_mock(["isd_id", "ad_id", "zookeepers"])
        server.topology.isd_id = 30
        server.topology.ad_id = 10
        server.topology.zookeepers = ["zk0", "zk1"]
        server._setup_parties = create_mock()
        # Call
        server.setup()
        # Tests
        zone_resolver.assert_called_once_with("lock", "domain")
        dns_server.assert_any_call(
            zone_resolver.return_value, port=SCION_DNS_PORT,
            address="127.0.0.1", server=SCIONDnsUdpServer,
            logger=dns_logger.return_value)
        dns_server.assert_any_call(
            zone_resolver.return_value, port=SCION_DNS_PORT,
            address="127.0.0.1", server=SCIONDnsTcpServer,
            logger=dns_logger.return_value)
        ntools.eq_(dns_server.call_count, 2)
        zookeeper.assert_called_once_with(
            30, 10, DNS_SERVICE, "srvid\0%d\000127.0.0.1" % SCION_DNS_PORT,
            ["zk0", "zk1"])
        ntools.eq_(server._parties, {})
        server._setup_parties.assert_called_once_with()


class TestSCIONDnsSetupParties(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._setup_parties
    """
    @patch("infrastructure.dns_server.SCIONDnsServer.__init__", autospec=True,
           return_value=None)
    def test(self, _):
        server = SCIONDnsServer("server_id", "domain", "topo_file")
        server.zk = create_mock(["retry", "party_setup"])
        server.topology = create_mock(["isd_id", "ad_id"])
        server.topology.isd_id = 30
        server.topology.ad_id = 10
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
                prefix="/ISD30-AD10/%s" % srv, autojoin=autojoin)
        ntools.eq_(server.zk.retry.call_count, len(server.SRV_TYPES))


class TestSCIONDnsSyncZkState(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._sync_zk_state
    """
    @patch("infrastructure.dns_server.SCIONDnsServer.__init__", autospec=True,
           return_value=None)
    def test_success(self, init):
        # Setup
        services = {
            BEACON_SERVICE: ["bs1", "bs2", "bs3"],
            CERTIFICATE_SERVICE: ["cs1"],
            DNS_SERVICE: ["ds1", "ds2"],
            PATH_SERVICE: [],
        }
        server = SCIONDnsServer("srvid", "domain", "topofile")
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

    @patch("infrastructure.dns_server.SCIONDnsServer.__init__", autospec=True,
           return_value=None)
    def test_no_conn(self, init):
        # Setup
        server = SCIONDnsServer("srvid", "domain", "topofile")
        server.zk = create_mock(['wait_connected'])
        server.zk.wait_connected.side_effect = ZkConnectionLoss
        # Call
        server._sync_zk_state()
        # Tests
        server.zk.wait_connected.assert_called_once_with(timeout=10.0)
        ntools.eq_(server.services, {})

    @patch("infrastructure.dns_server.SCIONDnsServer.__init__", autospec=True,
           return_value=None)
    def test_connloss(self, init):
        # Setup
        server = SCIONDnsServer("srvid", "domain", "topofile")
        server.zk = create_mock(['wait_connected'])
        server.domain = self.DOMAIN
        party = create_mock(["list"])
        party.list.side_effect = ZkConnectionLoss
        server._parties = {
            SCIONDnsServer.SRV_TYPES[0]: party
        }
        # Call
        server._sync_zk_state()


class TestSCIONDnsParseSrvInst(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._parse_srv_inst
    """
    @patch("infrastructure.dns_server.SCIONDnsServer.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        # Setup
        server = SCIONDnsServer("srvid", "domain", "topofile")
        srv_domain = self.DOMAIN.add(BEACON_SERVICE)
        server.services = {srv_domain: ["addr0"]}
        # Call
        server._parse_srv_inst("name\0port\0addr1\0addr2", srv_domain)
        # Tests
        ntools.eq_(server.services[srv_domain], ["addr0", "addr1", "addr2"])


class TestSCIONDnsRun(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer.run
    """
    @patch("infrastructure.dns_server.sleep")
    @patch("infrastructure.dns_server.SCIONDnsServer.__init__", autospec=True,
           return_value=None)
    def test(self, init, sleep):
        # Setup
        server = SCIONDnsServer("srvid", "domain", "topofile")
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
