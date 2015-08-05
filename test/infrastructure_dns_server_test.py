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
from functools import wraps
from unittest.mock import MagicMock, call, patch

# External packages
import nose
import nose.tools as ntools
from dnslib import DNSLabel, DNSRecord, QTYPE, RCODE

# SCION
from infrastructure.dns_server import SCIONDnsServer, ZoneResolver
from lib.defines import SCION_DNS_PORT
from lib.zookeeper import ZkConnectionLoss
from test.testcommon import MockCollection, SCIONTestError


class BaseDNSServer(object):
    """
    Base class for infrastructure.dns_server tests
    """
    DOMAIN = DNSLabel("testdomainpleaseignore")
    NAME = "notaninstance"
    FQDN = DOMAIN.add(NAME)

    def _setup_zoneresolver(self):
        self.lock = MagicMock(spec_set=["__enter__", "__exit__"])
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
        inst.resolve_forward = MagicMock(spec_set=[])
        request = MagicMock(spec_set=DNSRecord)
        reply = request.reply.return_value = "2345as"
        qname = request.q.qname = DNSLabel("a.tiny.teacup")
        request.q.qtype = QTYPE.A
        # Call
        ntools.eq_(inst.resolve(request, None), reply)
        # Tests
        inst.resolve_forward.assert_called_once_with(qname, "A", reply)

    def test_unsupported(self):
        # Setup
        inst = self._setup_zoneresolver()
        inst.resolve_forward = MagicMock(spec_set=[])
        inst.resolve_forward.side_effect = SCIONTestError(
            "Shouldn't be called")
        request = MagicMock(spec_set=DNSRecord)
        reply = request.reply.return_value = MagicMock(spec_set=["header"])
        reply.header = MagicMock(spec_set=["rcode"])
        request.q.qname = DNSLabel("a.tinier.teacup")
        request.q.qtype = QTYPE.MX
        # Call
        ntools.eq_(inst.resolve(request, None), reply)
        # Tests
        ntools.eq_(reply.header.rcode, RCODE.NXDOMAIN)


class TestZoneResolverResolveForward(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.ZoneResolver.resolve_forward
    """
    def test_outside_domain(self):
        # Setup
        inst = self._setup_zoneresolver()
        reply = MagicMock(spec_set=["header"])
        reply.header = MagicMock(spec_set=["rcode"])
        self.lock.__enter__.side_effect = SCIONTestError(
            "This should not have been reached")
        # Call
        inst.resolve_forward(DNSLabel("anotherdomain"), "A", reply)
        # Tests
        ntools.eq_(reply.header.rcode, RCODE.NOTAUTH)

    @patch("infrastructure.dns_server.A", autospec=True)
    @patch("infrastructure.dns_server.RR", autospec=True)
    def test_service_alias(self, rr, a):
        # Setup
        inst = self._setup_zoneresolver()
        reply = MagicMock(spec_set=['add_answer'])
        reply.add_answer = MagicMock(spec_set=[])
        srvalias = self.DOMAIN.add("bs")
        inst.services[srvalias] = ["127.0.1.22"]
        # Call
        inst.resolve_forward(srvalias, "A", reply)
        # Tests
        a.assert_called_once_with("127.0.1.22")
        rr.assert_called_once_with(srvalias, QTYPE.A, rdata=a.return_value)
        reply.add_answer.assert_called_once_with(rr.return_value)
        self.lock.__enter__.assert_called_once_with()

    def test_service_fail(self):
        # Setup
        inst = self._setup_zoneresolver()
        reply = MagicMock(spec_set=["header"])
        reply.header = MagicMock(spec_set=["rcode"])
        srvalias = self.DOMAIN.add("bs")
        inst.services[srvalias] = []
        # Call
        inst.resolve_forward(srvalias, "A", reply)
        # Tests
        ntools.eq_(reply.header.rcode, RCODE.SERVFAIL)

    def test_unknown(self):
        # Setup
        inst = self._setup_zoneresolver()
        reply = MagicMock(spec_set=["header"])
        reply.header = MagicMock(spec_set=["rcode"])
        # Call
        inst.resolve_forward(self.FQDN, "A", reply)
        # Tests
        ntools.eq_(reply.header.rcode, RCODE.NXDOMAIN)


def dns_init_wrapper(f):
    @wraps(f)
    def wrap(self, *args, **kwargs):
        if not hasattr(self, "mocks"):
            self.mocks = MockCollection()
        self.mocks.add('infrastructure.dns_server.SCIONElement.__init__',
                       'elem_init', new=MagicMock(spec_set=[]))
        self.mocks.add('infrastructure.dns_server.threading.Lock', 'lock')
        self.mocks.add('infrastructure.dns_server.SCIONElement.addr',
                       'elem_addr')
        self.mocks.start()
        try:
            return f(self, *args, **kwargs)
        finally:
            if hasattr(self, "mocks"):
                self.mocks.stop()
                del self.mocks
    return wrap


class TestSCIONDnsServerInit(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer.__init__
    """
    @dns_init_wrapper
    def test(self):
        # Call
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        # Tests
        self.mocks.elem_init.assert_called_once_with("ds", "topofile",
                                                     server_id="srvid")
        ntools.eq_(server.domain, self.DOMAIN)
        ntools.eq_(server.lock, self.mocks.lock.return_value)
        ntools.eq_(server.services, {})


def dns_setup_wrapper(f):
    @wraps(f)
    @dns_init_wrapper
    def wrap(self, *args, **kwargs):
        if not hasattr(self, "mocks"):
            self.mocks = MockCollection()
        self.mocks.add('infrastructure.dns_server.ZoneResolver',
                       'zone_resolver')
        self.mocks.add('infrastructure.dns_server.DNSServer', 'dns_server')
        self.mocks.add('infrastructure.dns_server.SCIONDnsLogger', 'dns_logger')
        self.mocks.add('infrastructure.dns_server.SCIONDnsUdpServer',
                       'dns_udp_server')
        self.mocks.add('infrastructure.dns_server.SCIONDnsTcpServer',
                       'dns_tcp_server')
        self.mocks.add('infrastructure.dns_server.Zookeeper', 'zookeeper')
        self.mocks.start()
        try:
            return f(self, *args, **kwargs)
        finally:
            if hasattr(self, "mocks"):
                self.mocks.stop()
                del self.mocks
    return wrap


class TestSCIONDnsServerSetup(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer.__init__
    """
    @dns_setup_wrapper
    def test(self):
        # Setup
        self.mocks.elem_addr.host_addr = "127.0.0.1"
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        server._setup_parties = MagicMock(spec_set=[])
        server.id = "srvid"
        server.topology = MagicMock(spec_set=["isd_id", "ad_id", "zookeepers"])
        server.topology.isd_id = 30
        server.topology.ad_id = 10
        server.topology.zookeepers = ["zk0", "zk1"]
        # Call
        server.setup()
        # Tests
        self.mocks.zone_resolver.assert_called_once_with(
            self.mocks.lock.return_value, self.DOMAIN)
        self.mocks.dns_server.assert_any_call(
            self.mocks.zone_resolver.return_value, port=SCION_DNS_PORT,
            address="127.0.0.1", server=self.mocks.dns_udp_server,
            logger=self.mocks.dns_logger.return_value)
        self.mocks.dns_server.assert_any_call(
            self.mocks.zone_resolver.return_value, port=SCION_DNS_PORT,
            address="127.0.0.1", server=self.mocks.dns_tcp_server,
            logger=self.mocks.dns_logger.return_value)
        ntools.eq_(self.mocks.dns_server.call_count, 2)
        self.mocks.zookeeper.assert_called_once_with(
            30, 10, "ds", "srvid\0%d\000127.0.0.1" % SCION_DNS_PORT,
            ["zk0", "zk1"])
        ntools.eq_(server._parties, {})
        server._setup_parties.assert_called_once_with()


class TestSCIONDnsSetupParties(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._setup_parties
    """
    def _setup_server(self):
        self.mocks.elem_addr.host_addr = "127.0.0.1"
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        server.id = "srvid"
        server.topology = MagicMock(spec_set=["isd_id", "ad_id"])
        server.topology.isd_id = 30
        server.topology.ad_id = 10
        server.zk = MagicMock(spec_set=["wait_connected", "_zk"])
        server._parties = {}
        server._setup_party = MagicMock(spec_set=[])
        return server

    @dns_init_wrapper
    def test_not_connected(self):
        # Setup
        server = self._setup_server()
        server.zk.wait_connected.side_effect = [False]
        # Call
        ntools.assert_raises(StopIteration, server._setup_parties)
        # Tests
        ntools.eq_(server.zk.wait_connected.call_count, 2)
        ntools.assert_false(server._setup_party.called)

    @dns_init_wrapper
    def test_setup(self):
        # Setup
        server = self._setup_server()
        server.zk.wait_connected.side_effect = [True]
        # Call
        server._setup_parties()
        # Tests
        server.zk.wait_connected.assert_called_once_with(timeout=10.0)
        calls = []
        for i in server.SRV_TYPES:
            calls.append(call(i))
        server._setup_party.assert_has_calls(calls)
        ntools.eq_(server._setup_party.call_count, len(server.SRV_TYPES))
        server._parties['ds'].join.assert_called_once_with()

    @dns_init_wrapper
    def test_connloss(self):
        # Setup
        server = self._setup_server()
        server.zk.wait_connected.side_effect = [True]
        server._setup_party.side_effect = [1, 2, 3, ZkConnectionLoss]
        # Call
        ntools.assert_raises(StopIteration, server._setup_parties)
        # Tests
        ntools.eq_(server.zk.wait_connected.call_count, 2)
        ntools.eq_(server._parties, {})


class TestSCIONDnsSetupParty(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._setup_party
    """
    @dns_init_wrapper
    def test(self):
        # Setup
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        server.topology = MagicMock(spec_set=["isd_id", "ad_id"])
        server.topology.isd_id = 30
        server.topology.ad_id = 10
        server.zk = MagicMock(spec_set=["party_setup"])
        prefix = "/ISD30-AD10/tst"
        # Call
        ret = server._setup_party("tst")
        # Tests
        server.zk.party_setup.assert_called_once_with(prefix=prefix, join=False)
        ntools.eq_(server.zk.party_setup.return_value, ret)


class TestSCIONDnsSyncZkState(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._sync_zk_state
    """
    _SRV_TYPES = ["bs", "cs"]
    _PARTIES = {
        "bs": "bs party",
        "cs": "cs party",
    }
    _BSES = ["bs1", "bs2", "bs3"]
    _CSES = ["cs1"]

    def _setup_server(self):
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        server.SRV_TYPES = self._SRV_TYPES
        server._parties = self._PARTIES
        server.zk = MagicMock(spec_set=['party_list'])
        server._parse_srv_inst = MagicMock(spec_set=[])
        server.resolver = MagicMock(spec_set=["services"])
        return server

    @dns_init_wrapper
    def test_success(self):
        # Setup
        server = self._setup_server()
        server.zk.party_list.side_effect = (self._BSES, self._CSES)
        domain_set = set([self.DOMAIN.add(srv) for srv in self._SRV_TYPES])
        # Call
        server._sync_zk_state()
        # Tests
        ntools.eq_(domain_set, set(server.services))
        list_calls = [call("bs party"), call("cs party")]
        server.zk.party_list.assert_has_calls(list_calls, any_order=True)
        bs_domain = self.DOMAIN.add("bs")
        cs_domain = self.DOMAIN.add("cs")
        parse_calls = [
            call("bs1", bs_domain),
            call("bs2", bs_domain),
            call("bs3", bs_domain),
            call("cs1", cs_domain),
        ]
        server._parse_srv_inst.assert_has_calls(parse_calls, any_order=True)
        ntools.assert_true(self.mocks.lock.called)
        ntools.eq_(server.resolver.services, server.services)

    @dns_init_wrapper
    def test_connloss(self):
        # Setup
        server = self._setup_server()
        server.zk.party_list.side_effect = [ZkConnectionLoss, self._CSES]
        # Call
        server._sync_zk_state()
        # Tests
        server._parse_srv_inst.assert_called_once_with(
            "cs1", self.DOMAIN.add("cs"))


class TestSCIONDnsParseSrvInst(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._mk_srv_inst
    """
    @dns_init_wrapper
    def test(self):
        # Setup
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        srv_domain = self.DOMAIN.add("bs")
        server.services[srv_domain] = ["addr0"]
        # Call
        server._parse_srv_inst("name\0port\0addr1\0addr2", srv_domain)
        # Tests
        ntools.eq_(server.services[srv_domain], ["addr0", "addr1", "addr2"])


class TestSCIONDnsRun(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer.run
    """
    @dns_init_wrapper
    @patch("infrastructure.dns_server.sleep")
    def test(self, sleep):
        # Setup
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        server._sync_zk_state = MagicMock(spec_set=[])
        server.udp_server = MagicMock(spec_set=["start_thread", "isAlive"])
        server.tcp_server = MagicMock(spec_set=["start_thread", "isAlive"])
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
