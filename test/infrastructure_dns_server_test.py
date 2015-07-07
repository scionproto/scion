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
from ipaddress import ip_address
from unittest.mock import MagicMock, call, patch

# External packages
import nose
import nose.tools as ntools
from dnslib import DNSLabel, DNSRecord, QTYPE, RCODE
from dnslib import A, AAAA, PTR, RR, SRV

# SCION
from infrastructure.dns_server import SCIONDnsServer, SrvInst, ZoneResolver
from lib.defines import SCION_DNS_PORT
from lib.zookeeper import ZkConnectionLoss, ConnectionLoss, SessionExpiredError
from test.testcommon import MockCollection, SCIONTestException


class BaseDNSServer(object):
    """
    Base class for infrastructure.dns_server tests
    """
    V4_ADDR = "169.254.0.11"
    V4_REVR = DNSLabel("11.0.254.169.in-addr.arpa")
    V6_ADDR = "FE80::0202:B3FF:FE1E:8329"
    V6_REVR = DNSLabel("9.2.3.8.e.1.e.f.f.f.3.b.2.0.2.0.0.0.0.0.0"
                       ".0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.")
    PORT = 26361
    DOMAIN = DNSLabel("testdomainpleaseignore")
    NAME = "notaninstance"
    FQDN = DOMAIN.add(NAME)

    def _setup_srvinst(self, data_items):
        data = "\0".join([str(item) for item in data_items])
        return SrvInst(data, self.DOMAIN)

    def _setup_zoneresolver(self):
        self.lock = MagicMock(spec_set=["__enter__", "__exit__"])
        return ZoneResolver(self.lock, self.DOMAIN, ["bs", "cs"])


class TestSrvInstInit(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SrvInst.__init__
    """
    def test_basic(self):
        # Call
        inst = self._setup_srvinst([self.NAME, str(self.PORT),
                                    self.V4_ADDR])
        # Tests
        ntools.eq_(inst.id, DNSLabel(self.NAME))
        ntools.eq_(inst.domain, self.DOMAIN)
        ntools.eq_(inst.fqdn,
                   DNSLabel("%s.%s" % (self.NAME,
                                       self.DOMAIN)))
        ntools.eq_(inst.port, self.PORT)
        ntools.eq_(inst.v4_addrs, [ip_address(self.V4_ADDR)])
        ntools.eq_(inst.v6_addrs, [])

    def test_v6(self):
        # Call
        inst = self._setup_srvinst([self.NAME, str(self.PORT),
                                    self.V6_ADDR])
        # Tests
        ntools.eq_(inst.v4_addrs, [])
        ntools.eq_(inst.v6_addrs, [ip_address(self.V6_ADDR)])

    def test_dual_stack(self):
        # Call
        inst = self._setup_srvinst([self.NAME, str(self.PORT),
                                    self.V6_ADDR, self.V4_ADDR])
        # Tests
        ntools.eq_(inst.v4_addrs, [ip_address(self.V4_ADDR)])
        ntools.eq_(inst.v6_addrs, [ip_address(self.V6_ADDR)])

    def test_multiple(self):
        # Call
        inst = self._setup_srvinst([self.NAME, str(self.PORT),
                                    self.V4_ADDR,
                                    self.V6_ADDR,
                                    "169.254.22.11",
                                    "FE80::0202:B3FF:FE1E:9123"])
        # Tests
        ntools.eq_(inst.v4_addrs,
                   [ip_address(self.V4_ADDR),
                    ip_address("169.254.22.11")])
        ntools.eq_(inst.v6_addrs,
                   [ip_address(self.V6_ADDR),
                    ip_address("FE80::0202:B3FF:FE1E:9123")])


class TestSrvInstReversePointers(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SrvInst.reverse_pointers
    """
    def test_basic(self):
        # Setup
        inst = self._setup_srvinst([self.NAME, str(self.PORT),
                                    self.V4_ADDR])
        # Call
        reply = inst.reverse_pointers()
        # Tests
        ntools.eq_(reply, [DNSLabel("11.0.254.169.in-addr.arpa.")])

    def test_v6(self):
        # Setup
        inst = self._setup_srvinst([self.NAME, str(self.PORT),
                                    self.V6_ADDR])
        # Call
        reply = inst.reverse_pointers()
        # Tests
        ntools.eq_(reply, [DNSLabel("9.2.3.8.e.1.e.f.f.f.3.b.2.0.2.0.0.0.0.0.0"
                                    ".0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.")])

    def test_dual_stack(self):
        # Setup
        inst = self._setup_srvinst([self.NAME, str(self.PORT),
                                    self.V6_ADDR, self.V4_ADDR])
        # Call
        reply = inst.reverse_pointers()
        # Tests
        ntools.eq_(len(reply), 2)
        ntools.assert_in(DNSLabel("11.0.254.169.in-addr.arpa."), reply)
        ntools.assert_in(DNSLabel("9.2.3.8.e.1.e.f.f.f.3.b.2.0.2.0.0.0.0.0.0"
                                  ".0.0.0.0.0.0.0.0.8.e.f.ip6.arpa."), reply)


class TestSrvInstForwardRecords(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SrvInst.forward_records
    """
    def _check(self, qname, qtype):
        # Setup
        fqdn = DNSLabel(self.DOMAIN).add(self.NAME)
        inst = self._setup_srvinst([self.NAME, str(self.PORT),
                                    self.V4_ADDR, self.V6_ADDR])
        reply = MagicMock(spec_set=DNSRecord)
        # SRV record should always be present
        answers = [(qname, QTYPE.SRV, SRV(target=fqdn, port=self.PORT))]
        # Only return A or AAAA records in answer section when queried directly
        # or via ANY
        if qtype in ["A", "ANY"]:
            answers.append((qname, QTYPE.A, A(self.V4_ADDR)))
        if qtype in ["AAAA", "ANY"]:
            answers.append((qname, QTYPE.AAAA, AAAA(self.V6_ADDR)))
        additional = []
        # Additional records should be included if:
        # a) it's a service request
        # b) it's an instance request and the record isn't already in the answer
        #    section
        if qname != fqdn or qtype not in ["A", "ANY"]:
            additional.append((fqdn, QTYPE.A, A(self.V4_ADDR)))
        if qname != fqdn or qtype not in ["AAAA", "ANY"]:
            additional.append((fqdn, QTYPE.AAAA, AAAA(self.V6_ADDR)))
        # Call
        inst.forward_records(qname, qtype, reply)
        # Tests
        for record, qtype, rdata in answers:
            reply.add_answer.assert_any_call(RR(record, qtype, rdata=rdata))
        ntools.eq_(reply.add_answer.call_count, len(answers))
        for record, qtype, rdata in additional:
            reply.add_ar.assert_any_call(RR(record, qtype, rdata=rdata))
        ntools.eq_(reply.add_ar.call_count, len(additional))

    def test_service(self):
        qname = self.DOMAIN.add("bs")
        for qtype in ["A", "AAAA", "ANY", "SRV", "SOA"]:
            yield self._check, qname, qtype

    def test_instance(self):
        qname = DNSLabel(self.DOMAIN).add(self.NAME)
        for qtype in ["A", "AAAA", "ANY", "SRV", "SOA"]:
            yield self._check, qname, qtype


class TestSrvInstReverseRecord(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SrvInst.reverse_record
    """
    def _check(self, reverse):
        # Setup
        fqdn = DNSLabel(self.DOMAIN).add(self.NAME)
        inst = self._setup_srvinst([self.NAME, str(self.PORT),
                                    self.V4_ADDR, self.V6_ADDR])
        reply = MagicMock(spec_set=DNSRecord)
        # Call
        inst.reverse_record(reverse, reply)
        # Tests
        reply.add_answer.assert_called_once_with(
            RR(reverse, QTYPE.PTR, rdata=PTR(label=fqdn)))

    def test(self):
        for rev in ("11.0.254.169.in-addr.arpa.",
                    "9.2.3.8.e.1.e.f.f.f.3.b.2.0.2.0.0.0.0.0.0"
                    ".0.0.0.0.0.0.0.0.8.e.f.ip6.arpa."):
            yield self._check, rev


class TestZoneResolverResolve(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.ZoneResolver.resolve
    """
    def _check_forward(self, qtype):
        # Setup
        inst = self._setup_zoneresolver()
        inst.resolve_forward = MagicMock(spec_set=[])
        inst.resolve_reverse = MagicMock(spec_set=[])
        request = MagicMock(spec_set=DNSRecord)
        reply = request.reply.return_value = "2345as"
        qname = request.q.qname = DNSLabel("a.tiny.teacup")
        request.q.qtype = getattr(QTYPE, qtype)
        # Call
        ntools.eq_(inst.resolve(request, None), reply)
        # Tests
        inst.resolve_forward.assert_called_once_with(qname, qtype, reply)
        ntools.eq_(inst.resolve_reverse.call_count, 0)

    def test_forward(self):
        for qtype in ["A", "AAAA", "ANY", "SRV"]:
            yield self._check_forward, qtype

    def test_reverse(self):
        # Setup
        inst = self._setup_zoneresolver()
        inst.resolve_forward = MagicMock(spec_set=[])
        inst.resolve_reverse = MagicMock(spec_set=[])
        request = MagicMock(spec_set=DNSRecord)
        reply = request.reply.return_value = "2345as"
        qname = request.q.qname = DNSLabel("teacup.tiny.a")
        request.q.qtype = QTYPE.PTR
        # Call
        ntools.eq_(inst.resolve(request, None), reply)
        # Tests
        ntools.eq_(inst.resolve_forward.call_count, 0)
        inst.resolve_reverse.assert_called_once_with(qname, reply)

    def test_unsupported(self):
        # Setup
        inst = self._setup_zoneresolver()
        inst.resolve_forward = MagicMock(spec_set=[])
        inst.resolve_reverse = MagicMock(spec_set=[])
        request = MagicMock(spec_set=DNSRecord)
        reply = request.reply.return_value = MagicMock(spec_set=["header"])
        reply.header = MagicMock(spec_set=["rcode"])
        request.q.qname = DNSLabel("a.tinier.teacup")
        request.q.qtype = QTYPE.MX
        # Call
        ntools.eq_(inst.resolve(request, None), reply)
        # Tests
        ntools.eq_(inst.resolve_forward.call_count, 0)
        ntools.eq_(inst.resolve_reverse.call_count, 0)
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
        self.lock.__enter__.side_effect = SCIONTestException(
            "This should not have been reached")
        # Call
        inst.resolve_forward(DNSLabel("anotherdomain"), "A", reply)
        # Tests
        ntools.eq_(reply.header.rcode, RCODE.NOTAUTH)

    def test_service_alias(self):
        # Setup
        inst = self._setup_zoneresolver()
        reply = MagicMock(spec_set=[])
        srvinst = MagicMock(spec_set=["forward_records"])
        srvalias = self.DOMAIN.add("bs")
        inst.services[srvalias] = [srvinst]
        # Call
        inst.resolve_forward(srvalias, "A", reply)
        # Tests
        srvinst.forward_records.assert_called_once_with(srvalias, "A", reply)
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

    def test_instance(self):
        # Setup
        inst = self._setup_zoneresolver()
        reply = MagicMock(spec_set=[])
        srvinst = MagicMock(spec_set=["forward_records"])
        inst.instances[self.FQDN] = srvinst
        # Call
        inst.resolve_forward(self.FQDN, "A", reply)
        # Tests
        srvinst.forward_records.assert_called_once_with(self.FQDN, "A", reply)

    def test_unknown(self):
        # Setup
        inst = self._setup_zoneresolver()
        reply = MagicMock(spec_set=["header"])
        reply.header = MagicMock(spec_set=["rcode"])
        # Call
        inst.resolve_forward(self.FQDN, "A", reply)
        # Tests
        ntools.eq_(reply.header.rcode, RCODE.NXDOMAIN)


class TestZoneResolverResolveReverse(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.ZoneResolver.resolve_reverse
    """
    def test_known(self):
        # Setup
        inst = self._setup_zoneresolver()
        reply = MagicMock(spec_set=[])
        srvinst = MagicMock(spec_set=["reverse_record"])
        inst.reverse[self.V4_REVR] = srvinst
        # Call
        inst.resolve_reverse(self.V4_REVR, reply)
        # Test
        srvinst.reverse_record.assert_called_once_with(self.V4_REVR, reply)
        self.lock.__enter__.assert_called_once_with()

    def test_unknown(self):
        # Setup
        inst = self._setup_zoneresolver()
        reply = MagicMock(spec_set=["header"])
        reply.header = MagicMock(spec_set=["rcode"])
        # Call
        inst.resolve_reverse(self.V4_REVR, reply)
        # Test
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
        server._join_parties = MagicMock(spec_set=[])
        server.id = "srvid"
        server.topology = MagicMock(spec_set=["isd_id", "ad_id"])
        server.topology.isd_id = 30
        server.topology.ad_id = 10
        # Call
        server.setup()
        # Tests
        self.mocks.zone_resolver.assert_called_once_with(
            self.mocks.lock.return_value, self.DOMAIN, server.SRV_TYPES)
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
            ["localhost:2181"])
        ntools.eq_(server._parties, {})
        server._join_parties.assert_called_once_with()


class TestSCIONDnsJoinParties(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._join_parties
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
        server._join_party = MagicMock(spec_set=[])
        return server

    @dns_init_wrapper
    def test_not_connected(self):
        # Setup
        server = self._setup_server()
        server.zk.wait_connected.side_effect = [False]
        server._join_party.side_effect = SCIONTestException(
            "_join_party should not have been called")
        # Call
        ntools.assert_raises(StopIteration, server._join_parties)
        # Tests
        ntools.eq_(server.zk.wait_connected.call_count, 2)

    @dns_init_wrapper
    def test_joining(self):
        # Setup
        server = self._setup_server()
        server.zk.wait_connected.side_effect = [True]
        # Call
        server._join_parties()
        # Tests
        ntools.eq_(server.zk.wait_connected.call_count, 1)
        calls = []
        for i in server.SRV_TYPES:
            calls.append(call(i))
        server._join_party.assert_has_calls(calls)
        ntools.eq_(server._join_party.call_count, len(server.SRV_TYPES))
        server._parties['ds'].join.assert_called_once_with()

    @dns_init_wrapper
    def test_connloss(self):
        # Setup
        server = self._setup_server()
        server.zk.wait_connected.side_effect = [True]
        server._join_party.side_effect = [1, 2, 3, ZkConnectionLoss]
        # Call
        ntools.assert_raises(StopIteration, server._join_parties)
        # Tests
        ntools.eq_(server.zk.wait_connected.call_count, 2)
        ntools.eq_(server._parties, {})


class TestSCIONDnsJoinParty(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._join_party
    """
    @dns_init_wrapper
    def test(self):
        # Setup
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        server.name_addrs = "nameaddrs"
        server.topology = MagicMock(spec_set=["isd_id", "ad_id"])
        server.topology.isd_id = 30
        server.topology.ad_id = 10
        server.zk = MagicMock(spec_set=["_zk"])
        server.zk._zk = MagicMock(spec_set=["Party", "ensure_path"])
        path = "/ISD30-AD10/tst/party"
        # Call
        ret = server._join_party("tst")
        # Tests
        server.zk._zk.ensure_path.assert_called_once_with(path)
        server.zk._zk.Party.assert_called_once_with(path, "nameaddrs")
        ntools.eq_(server.zk._zk.Party.return_value, ret)


class TestSCIONDnsSyncZkState(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._sync_zk_state
    """
    _SRV_TYPES = ["bs", "cs"]
    _PARTIES = {
        "bs": ["bs1", "bs2", "bs2"],
        "cs": ["cs1"],
    }

    def _setup_server(self):
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        server.SRV_TYPES = self._SRV_TYPES
        server._mk_srv_inst = MagicMock(spec_set=[])
        server._update_zone = MagicMock(spec_set=[])
        return server

    @patch.object(SCIONDnsServer, "SRV_TYPES", new=[])
    @dns_init_wrapper
    def test_success(self):
        # Setup
        server = self._setup_server()
        server._parties = self._PARTIES
        domain_set = set([self.DOMAIN.add(srv) for srv in self._SRV_TYPES])
        # Call
        server._sync_zk_state()
        # Tests
        ntools.eq_(domain_set, set(server.services))
        calls = []
        for srv, insts in self._PARTIES.items():
            srv_domain = self.DOMAIN.add(srv)
            for inst in set(insts):
                calls.append(call(inst, srv_domain))
        server._mk_srv_inst.assert_has_calls(calls, any_order=True)
        server._update_zone.assert_called_once_with()

    @dns_init_wrapper
    def _check_connloss(self, excp):
        # Setup
        server = self._setup_server()
        domain_set = set([self.DOMAIN.add(srv) for srv in server.SRV_TYPES])
        parties = MagicMock(spec_set=dict)
        # Redirect all server._parties read through _get_party_item,
        # simulating an exception during access.
        parties.__getitem__.side_effect = \
            lambda x: self._get_party_item(x, excp)
        server._parties = parties
        # Call
        server._sync_zk_state()
        # Tests
        ntools.eq_(domain_set, set(server.services))
        calls = []
        for srv, insts in self._PARTIES.items():
            if srv == "bs":
                continue
            srv_domain = self.DOMAIN.add(srv)
            for inst in set(insts):
                calls.append(call(inst, srv_domain))
        server._mk_srv_inst.assert_has_calls(calls, any_order=True)
        server._update_zone.assert_called_once_with()

    def test_connloss(self):
        for excp in ConnectionLoss, SessionExpiredError:
            yield self._check_connloss, excp

    def _get_party_item(self, item, excp):
        """
        Raise the specificed exception if a specified item is accessed
        """
        if item == "bs":
            raise excp
        else:
            return self._PARTIES[item]


class TestSCIONDnsMkSrvInst(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._mk_srv_inst
    """
    @patch("infrastructure.dns_server.SrvInst")
    @dns_init_wrapper
    def test(self, srv_inst):
        # Setup
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        srv_domain = self.DOMAIN.add("bs")
        server.services[srv_domain] = []
        srv_inst.return_value.fqdn = self.DOMAIN.add("inst")
        srv_inst.return_value.reverse_pointers.return_value = ["rev1", "rev2"]
        # Call
        server._mk_srv_inst("inst", srv_domain)
        # Tests
        srv_inst.assert_called_once_with("inst", self.DOMAIN)
        ntools.eq_(server.services, {srv_domain: [srv_inst.return_value]})
        ntools.eq_(server.instances,
                   {self.DOMAIN.add("inst"): srv_inst.return_value})
        ntools.eq_(server.reverse,
                   {"rev1": srv_inst.return_value,
                    "rev2": srv_inst.return_value})


class TestSCIONDnsUpdateZone(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._update_zone
    """
    @dns_init_wrapper
    def test(self):
        # Setup
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        server.lock = MagicMock(spec_set=["__enter__", "__exit__"])
        server.resolver = MagicMock(spec_set=["services", "instances",
                                              "reverse"])
        server._log_changes = MagicMock(spec_set=[])
        server._instance_names = MagicMock(spec_set=[])
        old_names = {"old", "names", ", honest"}
        new_names = {"truthfully", "new", "names", ", guv"}
        server._instance_names.side_effect = [old_names, new_names]
        srv_inst = MagicMock(spec_set=SrvInst)
        srv_inst.return_value.id = self.DOMAIN.add("inst_id")
        inst_obj = srv_inst()
        server.services = {"srv": [inst_obj]}
        server.instances = {"inst": inst_obj}
        server.reverse = {"rev": inst_obj}
        # Call
        server._update_zone()
        # Tests
        ntools.eq_(server.lock.__enter__.call_count, 1)
        ntools.eq_(server.lock.__exit__.call_count, 1)
        ntools.eq_(server.resolver.services, server.services)
        ntools.eq_(server.resolver.instances, server.instances)
        ntools.eq_(server.resolver.reverse, server.reverse)
        server._log_changes.assert_called_once_with(old_names, new_names)


class TestSCIONDnsLogChanges(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._log_changes
    """
    @dns_init_wrapper
    def _check(self, old, new, expect_added, expect_removed):
        # Setup
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        # Call
        added, removed = server._log_changes(old, new)
        # Tests
        ntools.eq_(expect_added, added)
        ntools.eq_(expect_removed, removed)

    def test(self):
        for old, new, added, removed in (
            [(), ("a", "b", "c"), ("a", "b", "c"), ()],
            [("a", "b", "c"), (), (), ("a", "b", "c")],
            [("a", "b", "c"), ("b", "c", "d"), ("d"), ("a")],
        ):
            yield self._check, set(old), set(new), set(added), set(removed)


class TestSCIONDnsInstanceNames(BaseDNSServer):
    """
    Unit tests for infrastructure.dns_server.SCIONDnsServer._instance_names
    """
    @dns_init_wrapper
    def test(self):
        # Setup
        server = SCIONDnsServer("srvid", self.DOMAIN, "topofile")
        instances = {}
        inst_names = []
        for i in range(3):
            inst = MagicMock(spec_set=SrvInst)()
            inst_name = "inst%d" % i
            inst.id = self.DOMAIN.add(inst_name)
            instances[inst_name] = inst
            inst_names.append("%s.%s" % (inst_name,
                                         str(self.DOMAIN).rstrip(".")))
        # Call
        ntools.eq_(server._instance_names(instances), set(inst_names))


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
