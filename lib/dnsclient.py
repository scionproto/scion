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
:mod:`lib.dnsclient` --- SCION DNS client library
=================================================
"""
# Stdlib
from ipaddress import ip_address
from random import shuffle

# External
import dns.exception
import dns.resolver
import dns.name
from dns.resolver import Resolver
from external.expiring_dict import ExpiringDict

# SCION
from lib.defines import SCION_DNS_PORT
from lib.errors import SCIONBaseError

#: Number of records to cache
DNS_CACHE_MAX_SIZE = 100
#: Seconds
DNS_CACHE_MAX_AGE = 60


class DNSLibBaseError(SCIONBaseError):
    """
    Base lib.dns exception
    """
    pass


class DNSLibMajorError(SCIONBaseError):
    """
    Base lib.dns major exception
    """
    pass


class DNSLibNoServersError(DNSLibMajorError):
    """
    No working servers
    """
    pass


class DNSLibNxDomain(DNSLibMajorError):
    """
    Name doesn't exist.
    """
    pass


class DNSLibMinorError(SCIONBaseError):
    """
    Base lib.dns minor exception
    """
    pass


class DNSLibTimeout(DNSLibMinorError):
    """
    Timeout
    """
    pass


class DNSClient(object):
    """
    DNS client class. Allows querying of dns_server for service instances.
    """
    def __init__(self, dns_servers, domain, lifetime=5.0):
        """
        :param [string] dns_servers: List of DNS servers IP addresses
        :param string domain: The DNS domain to query.
        :param float lifetime: Number of seconds in total to try resolving
                               before failing
        """
        self.resolver = Resolver(configure=False)
        self.resolver.nameservers = dns_servers
        self.resolver.port = SCION_DNS_PORT
        self.resolver.search = [dns.name.from_text(domain)]
        self.resolver.timeout = 1.0
        self.resolver.lifetime = lifetime

    def query(self, qname):
        """
        Lookup a DNS record via the Resolver.

        :param string qname: A relative DNS record to query. E.g. ``"bs"``
        :returns: A list of IP address objects
        :rtype: :class:`ipaddress._BaseAddress`
        :raises:
            DNSLibTimeout: No responses received.
            DNSLibNxDomain: Name doesn't exist.
            DNSLibError: Unexpected error.
        """
        try:
            results = self.resolver.query(qname)
        except dns.exception.Timeout:
            raise DNSLibTimeout("No responses within %ss" %
                                self.resolver.lifetime) from None
        except dns.resolver.NXDOMAIN:
            raise DNSLibNxDomain("Name (%s) does not exist" % qname) from None
        except dns.resolver.NoNameservers:
            raise DNSLibNoServersError("Unable to reach any working nameservers") \
                from None
        except Exception as e:
            raise DNSLibMajorError("Unhandled exception in resolver.") from e
        shuffle(results)
        return [ip_address(addr) for addr in results]


class DNSCachingClient(DNSClient):
    """
    Caching variant of the DNS client.
    """
    def __init__(self, dns_servers, domain, lifetime=5.0):
        """
        :param [string] dns_servers: List of DNS servers IP addresses
        :param string domain: The DNS domain to query.
        :param float lifetime: Number of seconds in total to try resolving
                               before failing
        """
        super().__init__(dns_servers, domain, lifetime=lifetime)
        self.cache = ExpiringDict(max_len=DNS_CACHE_MAX_SIZE,
                                  max_age_seconds=DNS_CACHE_MAX_AGE)

    def query(self, qname):
        """
        Check if the answer is already in the cache. If not, pass it along to
        the DNS client to query and cache the result.
        """
        answer = self.cache.get(qname)
        if answer is None:
            answer = super().query(qname)
            self.cache[qname] = answer
        shuffle(answer)
        return answer
