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
from unittest.mock import MagicMock, call, patch

# External packages
import dns
import nose
import nose.tools as ntools

# SCION
from lib.defines import SCION_DNS_PORT
from lib.dnsclient import (
    DNSClient,
    DNSLibException,
    DNSLibTimeout,
)


class TestDNSClientInit(object):
    """
    Unit tests for lib.dnsclient.DNSClient.__init__
    """
    @patch("lib.dnsclient.dns.name.from_text", autospec=True)
    @patch("lib.dnsclient.Resolver", autospec=True)
    def test(self, resolver, from_text):
        # Setup
        attrs = ["nameservers", "port", "search", "timeout", "lifetime"]
        res_inst = MagicMock(spec_set=attrs)
        resolver.return_value = res_inst
        # Call
        client = DNSClient(["ip1", "ip2"], "domain", lifetime=30.0)
        # Tests
        resolver.assert_called_once_with(configure=False)
        ntools.eq_(client.resolver, res_inst)
        ntools.eq_(res_inst.nameservers, ["ip1", "ip2"])
        ntools.eq_(res_inst.port, SCION_DNS_PORT)
        ntools.eq_(res_inst.search, [from_text.return_value])
        ntools.eq_(res_inst.timeout, 1.0)
        ntools.eq_(res_inst.lifetime, 30.0)

    @patch("lib.dnsclient.dns.name.from_text", autospec=True)
    @patch("lib.dnsclient.Resolver", autospec=True)
    def test_less_args(self, resolver, from_text):
        # Setup
        attrs = ["nameservers", "port", "search", "timeout", "lifetime"]
        res_inst = MagicMock(spec_set=attrs)
        resolver.return_value = res_inst
        # Call
        DNSClient(["ip1", "ip2"], "domain")
        # Tests
        ntools.eq_(res_inst.lifetime, 5.0)


class TestDNSClientQuery(object):
    """
    Unit tests for lib.dnsclient.DNSClient.query
    """
    @patch("lib.dnsclient.dns.name.from_text", autospec=True)
    @patch("lib.dnsclient.Resolver", autospec=True)
    def _setup(self, resolver, from_text, addrs=None):
        attrs = ["nameservers", "port", "query", "search", "timeout",
                 "lifetime"]
        res_inst = MagicMock(spec_set=attrs)
        res_inst.query = MagicMock(spec_set=[])
        resolver.return_value = res_inst
        if not addrs:
            addrs = ["ip1", "ip2"]
        return DNSClient(addrs, "domain")

    @patch("lib.dnsclient.ip_address", spec_set=[], new_callable=MagicMock)
    def test_basic(self, ipaddr):
        # Setup
        client = self._setup()
        client.resolver.query.return_value = ["result0", "result1"]
        ipaddr.side_effect = ["ip0", "ip1"]
        # Call
        ntools.eq_(client.query("search string"), ["ip0", "ip1"])
        # Tests
        client.resolver.query.assert_called_once_with("search string")
        ipaddr.assert_has_calls([call("result0"), call("result1")],
                                any_order=True)

    def _check_exceptions(self, error, excp):
        # Setup
        client = self._setup()
        client.resolver.query.side_effect = error
        # Call
        ntools.assert_raises(excp, client.query, "test")

    def test_exceptions(self):
        for error, excp in (
            (dns.exception.Timeout, DNSLibTimeout),
            (dns.resolver.NXDOMAIN, DNSLibException),
            (dns.resolver.YXDOMAIN, DNSLibException),
            (dns.resolver.NoAnswer, DNSLibException),
            (dns.resolver.NoNameservers, DNSLibException),
        ):
            yield self._check_exceptions, error, excp


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
