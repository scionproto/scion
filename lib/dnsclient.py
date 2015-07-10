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

# SCION
from lib.defines import SCION_DNS_PORT


class DNSLibException(Exception):
    pass


class DNSLibTimeout(DNSLibException):
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
        """
        try:
            results = self.resolver.query(qname)
        except dns.exception.Timeout:
            raise DNSLibTimeout("No responses within %ss" %
                                self.resolver.lifetime) from None
        except dns.resolver.NXDOMAIN:
            raise DNSLibException("Name (%s) does not exist" % qname) from None
        except Exception as e:
            raise DNSLibException("Unhandled exception in resolver.") from e
        shuffle(results)
        return [ip_address(addr) for addr in results]
