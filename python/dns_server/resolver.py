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
:mod:`resolver` --- Resolver to handle queries
==============================================
"""

# Stdlib
import logging
import time

# External packages
from dnslib import A, QTYPE, RCODE, RR
from dnslib.server import BaseResolver

# SCION
from lib.defines import STARTUP_QUIET_PERIOD


class ZoneResolver(BaseResolver):
    """
    Handle DNS queries.
    """

    def __init__(self, lock, domain):  # pragma: no cover
        """
        Initialize an instance of the class ZoneResolver.

        :param lock: Lock to coordinate access to instance data.
        :type lock: threading.Lock
        :param domain: Parent DNS domain.
        :type domain:
        """
        self.lock = lock
        self.domain = domain
        self.services = {}
        self._startup = time.time()

    def resolve(self, request, _):
        """
        Respond to DNS request.

        :param dnslib.DNSRecord request: DNS request.

        :returns: The DNS reply to send.
        :rtype: `dnslib.DNSRecord`
        """
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]

        if qtype == "A":
            self.resolve_forward(qname, qtype, reply)
        else:
            # Not a request type we support
            logging.warning("Unsupported query type: %s", qtype)
            reply.header.rcode = RCODE.NXDOMAIN
        return reply

    def resolve_forward(self, qname, qtype, reply):
        """
        Build a response to a forward DNS query (i.e. one that contains a
        hostname)

        :param dnslib.DNSRecord qname: The query's target.
        :param str qtype: The type of query (e.g. ``"SRV"``)
        :param dnslib.DNSRecord reply: The DNSRecord to populate with the reply.
        """
        # Request isn't even in our domain
        if not qname.matchSuffix(self.domain):
            logging.warning("Rejecting query outside our domain: %s", qname)
            reply.header.rcode = RCODE.NOTAUTH
            return
        with self.lock:
            # Is the request for a service alias?
            for srv_domain, addrs in self.services.items():
                if qname.matchSuffix(srv_domain):
                    if not addrs:
                        if (time.time() - self._startup > STARTUP_QUIET_PERIOD):
                            logging.warning("No instances found, returning "
                                            "SERVFAIL for %s", qname)
                        # If there are no instances, we are unable to read from
                        # ZK (or else the relevant service is down), so return
                        # SERVFAIL
                        reply.header.rcode = RCODE.SERVFAIL
                        return
                    for addr in addrs:
                        reply.add_answer(RR(qname, QTYPE.A, rdata=A(addr)))
                    return
            logging.warning("Unknown service: %s", qname)
            reply.header.rcode = RCODE.NXDOMAIN
