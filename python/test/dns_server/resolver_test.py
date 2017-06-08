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
:mod:`resolver_test` --- dns_server.resolver unit tests
======================================================================
"""
# Stdlib
from unittest.mock import call, patch, create_autospec

# External packages
import nose
import nose.tools as ntools
from dnslib import DNSLabel, DNSRecord, QTYPE, RCODE

# SCION
from dns_server.resolver import ZoneResolver
from lib.defines import BEACON_SERVICE
from test.testcommon import create_mock


class BaseDNSServer(object):
    DOMAIN = DNSLabel("testdomainpleaseignore")
    NAME = "notaninstance"
    FQDN = DOMAIN.add(NAME)

    def _setup_zoneresolver(self):
        self.lock = create_mock(["__enter__", "__exit__"])
        return ZoneResolver(self.lock, self.DOMAIN)


class TestZoneResolverResolve(BaseDNSServer):
    """
    Unit tests for dns_server.resolver.ZoneResolver.resolve
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

    @patch("dns_server.resolver.logging.warning", autospec=True)
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
    Unit tests for
    dns_server.resolver.ZoneResolver.resolve_forward
    """
    @patch("dns_server.resolver.logging.warning", autospec=True)
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

    @patch("dns_server.resolver.A", autospec=True)
    @patch("dns_server.resolver.RR", autospec=True)
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

    @patch("dns_server.resolver.logging.warning", autospec=True)
    def test_service_fail(self, warning):
        # Setup
        inst = self._setup_zoneresolver()
        reply = create_mock(["header"])
        reply.header = create_mock(["rcode"])
        srvalias = self.DOMAIN.add(BEACON_SERVICE)
        inst.services[srvalias] = []
        inst._startup = 0
        # Call
        inst.resolve_forward(srvalias, "A", reply)
        # Tests
        ntools.ok_(warning.called)
        ntools.eq_(reply.header.rcode, RCODE.SERVFAIL)

    @patch("dns_server.resolver.logging.warning", autospec=True)
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


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
