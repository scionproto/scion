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
:mod:`lib_dnsclient_test` --- lib.dnsclient unit tests
======================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import dns
import nose
import nose.tools as ntools
from dns.rdatatype import A, AAAA, AXFR

# SCION
from lib.defines import SCION_DNS_PORT
from lib.dnsclient import (
    DNSCachingClient,
    DNSClient,
    DNSLibMajorError,
    DNSLibMinorError,
    DNSLibNoServersError,
    DNSLibNxDomain,
    DNSLibTimeout,
)
from test.testcommon import create_mock


class TestDNSClientInit(object):
    """
    Unit tests for lib.dnsclient.DNSClient.__init__
    """
    @patch("lib.dnsclient.dns.name.from_text", autospec=True)
    @patch("lib.dnsclient.Resolver", autospec=True)
    def test_full(self, resolver, from_text):
        # Setup
        res_inst = create_mock(
            ["nameservers", "port", "search", "timeout", "lifetime"])
        resolver.return_value = res_inst
        # Call
        client = DNSClient(["ip1", "ip2"], "domain", lifetime=30.0, port=102)
        # Tests
        resolver.assert_called_once_with(configure=False)
        ntools.eq_(client.resolver, res_inst)
        ntools.eq_(res_inst.nameservers, ["ip1", "ip2"])
        ntools.eq_(res_inst.search, [from_text.return_value])
        ntools.eq_(res_inst.port, 102)
        ntools.eq_(res_inst.timeout, 1.0)
        ntools.eq_(res_inst.lifetime, 30.0)

    @patch("lib.dnsclient.dns.name.from_text", autospec=True)
    @patch("lib.dnsclient.Resolver", autospec=True)
    def test_less_args(self, resolver, from_text):
        # Setup
        res_inst = create_mock(
            ["nameservers", "port", "search", "timeout", "lifetime"])
        resolver.return_value = res_inst
        # Call
        DNSClient(["ip1", "ip2"], "domain")
        # Tests
        ntools.eq_(res_inst.lifetime, 5.0)
        ntools.eq_(res_inst.port, SCION_DNS_PORT)


class TestDNSClientQuery(object):
    """
    Unit tests for lib.dnsclient.DNSClient.query
    """
    def _setup(self):
        inst = DNSClient(["ip1", "ip2"], "domain")
        inst.resolver = create_mock(["nameservers", "port", "search", "timeout",
                                     "lifetime", "query"])
        return inst

    @patch("lib.dnsclient.DNSClient._parse_answer", autospec=True)
    @patch("lib.dnsclient.DNSClient.__init__", autospec=True, return_value=None)
    def test_basic(self, init, parse_ans):
        # Setup
        client = self._setup()
        # Call
        ntools.eq_(client.query("search string"), parse_ans.return_value)
        # Tests
        client.resolver.query.assert_called_once_with("search string", "A")
        parse_ans.assert_called_once_with(client,
                                          client.resolver.query.return_value)

    @patch("lib.dnsclient.DNSClient.__init__", autospec=True, return_value=None)
    def _check_exceptions(self, error, excp, init):
        # Setup
        client = self._setup()
        client.resolver.query.side_effect = error
        # Call
        ntools.assert_raises(excp, client.query, "test")

    def test_exceptions(self):
        for error, excp in (
            (dns.exception.Timeout, DNSLibTimeout),
            (dns.resolver.NXDOMAIN, DNSLibNxDomain),
            (dns.resolver.YXDOMAIN, DNSLibMajorError),
            (dns.resolver.NoAnswer, DNSLibMajorError),
            (dns.resolver.NoNameservers, DNSLibNoServersError),
        ):
            yield self._check_exceptions, error, excp


class TestDNSClientParseAnswer(object):
    """
    Unit tests for lib.dnsclient.DNSClient._parse_answer
    """
    @patch("lib.dnsclient.logging.debug", autospec=True)
    @patch("lib.dnsclient.shuffle", autospec=True)
    @patch("lib.dnsclient.haddr_parse", autospec=True)
    @patch("lib.dnsclient.DNSClient.__init__", autospec=True, return_value=None)
    def test(self, init, hparse, shuffle, debug):
        inst = DNSClient("servers", "domain")
        answer = []
        types = [A, AAAA, A, A, AXFR, AAAA]
        for i, type_ in enumerate(types):
            ans_mock = create_mock(["__str__", "rdtype"])
            ans_mock.rdtype = type_
            ans_mock.__str__.return_value = "r%s" % i
            answer.append(ans_mock)
        hparse.side_effect = lambda type_, addr: "%s:%s" % (type_, addr)
        results = ["IPV4:r0", "IPV6:r1", "IPV4:r2", "IPV4:r3", "IPV6:r5"]
        # Call
        ntools.eq_(inst._parse_answer(answer), results)
        # Tests
        ntools.eq_(debug.call_count, 1)
        shuffle.assert_called_once_with(results)


class TestDNSCachingClientQuery(object):
    """
    Unit tests for lib.dnsclient.DNSCachingClient.query
    """
    @patch("lib.dnsclient.shuffle", autospec=True)
    @patch("lib.dnsclient.DNSCachingClient.__init__", autospec=True,
           return_value=None)
    def test_cache_hit(self, init, shuffle):
        # Setup
        client = DNSCachingClient("servers", "domain", "lifetime")
        client.cache = create_mock(["get"])
        # Call
        ntools.eq_(client.query("blah"), client.cache.get.return_value)
        # Tests
        shuffle.assert_called_once_with(client.cache.get.return_value)

    @patch("lib.dnsclient.shuffle", autospec=True)
    @patch("lib.dnsclient.DNSClient.query", autospec=True)
    @patch("lib.dnsclient.DNSCachingClient.__init__", autospec=True,
           return_value=None)
    def test_success(self, init, client_query, shuffle):
        # Setup
        client = DNSCachingClient("servers", "domain", "lifetime")
        client.cache = create_mock(["get", "__setitem__"])
        client.cache.get.return_value = None
        # Call
        ntools.eq_(client.query("blah"), client_query.return_value)
        # Tests
        client.cache.get.assert_called_once_with("blah")
        client.cache.__setitem__.assert_called_once_with(
            "blah", client_query.return_value)

    @patch("lib.dnsclient.DNSClient.query", autospec=True)
    @patch("lib.dnsclient.DNSCachingClient.__init__", autospec=True,
           return_value=None)
    def test_fail_no_fallback(self, init, client_query):
        # Setup
        client = DNSCachingClient("servers", "domain", "lifetime")
        client.cache = create_mock(["get"])
        client.cache.get.return_value = None
        client_query.side_effect = DNSLibMajorError
        # Call
        ntools.assert_raises(DNSLibMajorError, client.query, "blah")

    @patch("lib.dnsclient.shuffle", autospec=True)
    @patch("lib.dnsclient.logging.log", autospec=True)
    @patch("lib.dnsclient.DNSClient.query", autospec=True)
    @patch("lib.dnsclient.DNSCachingClient.__init__", autospec=True,
           return_value=None)
    def _check_fail_with_fallback(self, excp, init, client_query, log,
                                  shuffle):
        # Setup
        client = DNSCachingClient("servers", "domain", "lifetime")
        client.cache = create_mock(["get", "__setitem__"])
        client.cache.get.return_value = None
        client_query.side_effect = excp
        log.side_effect = lambda level, format_, *args: format_ % args
        fallback = "fallback"
        # Call
        ntools.eq_(client.query("blah", fallback), fallback)
        # Tests
        client.cache.__setitem__.assert_called_once_with("blah", fallback)

    def test_fail_with_fallback(self):
        for excp in (DNSLibMinorError, DNSLibMajorError):
            yield self._check_fail_with_fallback, excp

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
