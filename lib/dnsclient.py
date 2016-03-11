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
:mod:`dnsclient` --- SCION DNS client library
=============================================
"""
# Stdlib
import logging
from random import shuffle

# External
import dns.exception
import dns.name
import dns.resolver
from dns.resolver import Resolver
from external.expiring_dict import ExpiringDict

# SCION
from lib.defines import SCION_DNS_PORT
from lib.errors import SCIONBaseError
from lib.packet.host_addr import haddr_parse

#: Number of records to cache.
DNS_CACHE_MAX_SIZE = 100
#: Cache validity in seconds. Probably should use DNS TTL in future.
DNS_CACHE_MAX_AGE = 60


class DNSLibBaseError(SCIONBaseError):
    """
    Base lib.dnsclient exception.
    """
    pass


class DNSLibMajorError(DNSLibBaseError):
    """
    Base lib.dnsclient major exception.
    """
    pass


class DNSLibNoServersError(DNSLibMajorError):
    """
    No working servers.
    """
    pass


class DNSLibNxDomain(DNSLibMajorError):
    """
    Name doesn't exist.
    """
    pass


class DNSLibMinorError(DNSLibBaseError):
    """
    Base lib.dnsclient minor exception.
    """
    pass


class DNSLibTimeout(DNSLibMinorError):
    """
    DNS Timeout.
    """
    pass


class DNSClient(object):
    """
    DNS client class. Allows querying of `dns_server` for service discovery.
    """
    def __init__(self, dns_servers, domain, lifetime=5.0, port=SCION_DNS_PORT):
        """
        :param list dns_servers:
            DNS server IP addresses as strings. E.g. ``["127.0.0.1",
            "8.8.8.8"]``
        :param string domain: The DNS domain to query.
        :param float lifetime:
            Number of seconds in total to try resolving before failing.
        :param int port: DNS server port.
        """
        self.resolver = Resolver(configure=False)
        self.resolver.nameservers = dns_servers
        self.resolver.search = [dns.name.from_text(domain)]
        self.resolver.port = port
        self.resolver.timeout = 1.0
        self.resolver.lifetime = lifetime

    def query(self, qname):
        """
        Lookup a DNS record via the Resolver.

        :param string qname: A relative DNS record to query. E.g. ``"bs"``
        :returns: A list of `Host address <HostAddrBase>`_ objects.
        :raises:
            DNSLibTimeout: No responses received.
            DNSLibNxDomain: Name doesn't exist.
            DNSLibError: Unexpected error.
        """
        try:
            # TODO(kormat): This needs to be more general, ideally using `ANY`,
            # but dnspython's resolver currently does not support it :/
            # https://github.com/rthalley/dnspython/issues/117
            answer = self.resolver.query(qname, "A")
        except dns.exception.Timeout:
            raise DNSLibTimeout("No responses within %ss" %
                                self.resolver.lifetime) from None
        except dns.resolver.NXDOMAIN:
            raise DNSLibNxDomain("Name (%s) does not exist" % qname) from None
        except dns.resolver.NoNameservers:
            raise DNSLibNoServersError(
                "Unable to reach any working nameservers") from None
        except Exception as e:
            raise DNSLibMajorError("Unhandled exception in resolver.") from e
        return self._parse_answer(answer)

    def _parse_answer(self, answer):
        """
        Parse DNS answer into host addresses.

        :param `dnslib.resolver.Answer` answer:
        :returns: List of `Host addresses <HostAddrBase>`_ objects.
        """
        addrs = []
        for record in answer:
            if record.rdtype == dns.rdatatype.A:
                addrs.append(haddr_parse("IPV4", str(record)))
            elif record.rdtype == dns.rdatatype.AAAA:
                addrs.append(haddr_parse("IPV6", str(record)))
            else:
                logging.debug("Ignoring unsupported dns record type (%s): %r",
                              dns.rdatatype._by_value[record.rdtype], record)
        shuffle(addrs)
        return addrs


class DNSCachingClient(DNSClient):
    """
    Caching variant of the DNS client.
    """
    def __init__(self, dns_servers, domain, lifetime=5.0):  # pragma: no cover
        """
        :param list dns_servers:
            DNS server IP addresses as strings. E.g. ``["127.0.0.1",
            "8.8.8.8"]``
        :param string domain: The DNS domain to query.
        :param float lifetime:
            Number of seconds in total to try resolving before failing.
        """
        super().__init__(dns_servers, domain, lifetime=lifetime)
        self.cache = ExpiringDict(max_len=DNS_CACHE_MAX_SIZE,
                                  max_age_seconds=DNS_CACHE_MAX_AGE)

    def query(self, qname, fallback=None, quiet=False):
        """
        Check if the answer is already in the cache. If not, pass it along to
        the DNS client and cache the result.

        :param string qname: A relative DNS record to query. E.g. ``"bs"``
        :param list fallback:
            If provided, and the DNS query fails, use this as the answer
            instead.
        :param bool quiet: If set, don't log warnings/errors.
        :returns: A list of `Host address <HostAddrBase>`_ objects.
        :raises:
            DNSLibTimeout: No responses received.
            DNSLibNxDomain: Name doesn't exist.
            DNSLibError: Unexpected error.
        """
        answer = self.cache.get(qname)
        if answer is None:
            answer = fallback
            try:
                answer = super().query(qname)
            except DNSLibBaseError as e:
                if fallback is None:
                    raise
                if isinstance(e, DNSLibMinorError):
                    level = logging.WARN
                else:
                    level = logging.ERROR
                if not quiet:
                    logging.log(
                        level, "DNS failure, using fallback value for %s: %s",
                        qname, e)
            self.cache[qname] = answer
        shuffle(answer)
        return answer
