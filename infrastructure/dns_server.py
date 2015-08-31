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
:mod:`dns_server` --- SCION DNS server
======================================
This is a custom DNS server, built on Paul Chakravarti's `dnslib
<https://bitbucket.org/paulc/dnslib>`_.

It dynamically provides DNS records for the AD based on service instances
registering in Zookeeper.
"""
# Stdlib
import argparse
import binascii
import datetime
import logging
import sys
import threading
from time import sleep

# External packages
from dnslib import A, DNSLabel, QTYPE, RCODE, RR
from dnslib.server import (
    BaseResolver,
    DNSLogger,
    DNSServer,
    TCPServer,
    UDPServer,
)

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    DNS_SERVICE,
    PATH_SERVICE,
    SCION_DNS_PORT,
)
from lib.log import init_logging, log_exception
from lib.thread import kill_self
from lib.util import handle_signals, trace
from lib.zookeeper import ZkConnectionLoss, Zookeeper


class ZoneResolver(BaseResolver):
    """
    Handle DNS queries.
    """

    def __init__(self, lock, domain):
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


class SCIONDnsTcpServer(TCPServer):
    """
    Sub-class to provide thread naming and error handling for
    dnslib.server.TCPServer
    """

    def serve_forever(self):
        cur_thread = threading.current_thread()
        cur_thread.name = "DNS service - TCP"
        super().serve_forever()

    def handle_error(self, *args, **kwargs):
        log_exception("Error when serving DNS request:")
        kill_self()


class SCIONDnsUdpServer(UDPServer):
    """
    Sub-class to provide thread naming and error handling for
    dnslib.server.UDPServer
    """

    def serve_forever(self):
        cur_thread = threading.current_thread()
        cur_thread.name = "DNS service - UDP"
        super().serve_forever()

    def handle_error(self, *args, **kwargs):
        log_exception("Error when serving DNS request:")
        kill_self()


class SCIONDnsLogger(DNSLogger):  # pragma: no cover
    """
    Sub-class to log DNS events instead of just printing them to stdout.

    See `the dns lib source
    <https://bitbucket.org/paulc/dnslib/src/
    68842cf47aca1d283ea4f87bf46d07a3f96e598a/
    dnslib/server.py?at=default#cl-193>`_
    for how to configure what gets logged.
    """

    def __init__(self, *args, level=logging.DEBUG, **kwargs):
        self.level = level
        super().__init__(*args, **kwargs)

    def log_prefix(self, handler):
        return ""

    def _common_prefix(self, handler, data):
        return "[%s:%d] (%s)" % (handler.client_address[0],
                                 handler.client_address[1], handler.protocol)

    def _reply_prefix(self, handler, reply, desc):
        return "%s: %s / '%s' (%s) /" % (
            desc, self._common_prefix(handler, reply), reply.q.qname,
            QTYPE[reply.q.qtype])

    def _format_rrs(self, reply):
        return "RRs: %s" % ",".join([QTYPE[a.rtype] for a in reply.rr])

    def log_recv(self, handler, data):
        logging.log(self.level, "Received: %s <%d> : %s",
                    self._common_prefix(handler, data), len(data),
                    binascii.hexlify(data))

    def log_send(self, handler, data):
        logging.log(self.level, "Sent: %s <%d> : %s",
                    self._common_prefix(handler, data), len(data),
                    binascii.hexlify(data))

    def log_request(self, handler, request):
        logging.log(self.level, "Request: %s / '%s' (%s)",
                    self._common_prefix(handler, request), request.q.qname,
                    QTYPE[request.q.qtype])
        self.log_data(request)

    def log_reply(self, handler, reply):
        level = self.level
        output = [self._reply_prefix(handler, reply, "Reply")]
        if reply.header.rcode == RCODE.NOERROR:
            output.append(self._format_rrs(reply))
        else:
            level = logging.WARNING
            output.append(RCODE[reply.header.rcode])
        logging.log(level, " ".join(output))
        self.log_data(reply)

    def log_truncated(self, handler, reply):
        level = self.level
        logging.log(level, "%s %s",
                    self._reply_prefix(handler, reply, "Truncated Reply"),
                    self._format_rrs(reply))
        self.log_data(reply)

    def log_error(self, handler, e):
        logging.log(logging.ERROR, "Invalid Request: %s :: %s",
                    self._common_prefix(handler, e), e)

    def log_data(self, dnsobj):
        for line in dnsobj.toZone("    ").split("\n"):
            logging.log(self.level, line)


class SCIONDnsServer(SCIONElement):
    """
    SCION DNS Server. Responsible for starting the DNS resolver threads, and
    frequently updating the shared instance data from ZK.

    :cvar float SYNC_TIME: How frequently (in seconds) to update the shared
                           instance data from ZK.
    :cvar list SRV_TYPES: Service types to monitor/export
    """
    SYNC_TIME = 1.0
    SRV_TYPES = (BEACON_SERVICE, CERTIFICATE_SERVICE, DNS_SERVICE, PATH_SERVICE)

    def __init__(self, server_id, domain, topo_file):
        """
        :param str server_id: Local id of the server, E.g. '3'.
        :param str domain: DNS domain to serve.
        :param str topo_file: Path to topology file.
        """
        super().__init__(DNS_SERVICE, topo_file, server_id=server_id)
        self.domain = DNSLabel(domain)
        self.lock = threading.Lock()
        self.services = {}

    def setup(self):
        """
        Set up various servers and connections required.
        """
        self.resolver = ZoneResolver(self.lock, self.domain)
        self.udp_server = DNSServer(self.resolver, port=SCION_DNS_PORT,
                                    address=str(self.addr.host_addr),
                                    server=SCIONDnsUdpServer,
                                    logger=SCIONDnsLogger())
        self.tcp_server = DNSServer(self.resolver, port=SCION_DNS_PORT,
                                    address=str(self.addr.host_addr),
                                    server=SCIONDnsTcpServer,
                                    logger=SCIONDnsLogger())
        self.name_addrs = "\0".join([self.id, str(SCION_DNS_PORT),
                                     str(self.addr.host_addr)])
        self.zk = Zookeeper(
            self.topology.isd_id, self.topology.ad_id,
            DNS_SERVICE, self.name_addrs, self.topology.zookeepers)
        self._parties = {}
        self._setup_parties()

    def _setup_parties(self):
        """
        Join all the necessary ZK parties.
        """
        logging.debug("Joining parties")
        for type_ in self.SRV_TYPES:
            prefix = "/ISD%d-AD%d/%s" % (self.topology.isd_id,
                                         self.topology.ad_id, type_)
            autojoin = False
            # Join only the DNS service party, for the rest we just want to
            # setup the party so we can monitor the members.
            if type_ == DNS_SERVICE:
                autojoin = True
            self._parties[type_] = self.zk.retry(
                "Joining %s party" % type_, self.zk.party_setup, prefix=prefix,
                autojoin=autojoin)

    def _sync_zk_state(self):
        """
        Update shared instance data from ZK.
        """
        # Clear existing state
        self.services = {}

        try:
            self.zk.wait_connected(timeout=10.0)
        except ZkConnectionLoss:
            logging.warning("No connection to Zookeeper, can't update services")
            return

        # Retrieve alive instance details from ZK for each service.
        for srv_type in self.SRV_TYPES:
            srv_domain = self.domain.add(srv_type)
            self.services[srv_domain] = []
            party = self._parties[srv_type]
            try:
                srvs = party.list()
            except ZkConnectionLoss:
                # If the connection drops, don't update
                return
            for i in srvs:
                self._parse_srv_inst(i, srv_domain)

        # Update DNS zone data
        with self.lock:
            self.resolver.services = self.services

    def _parse_srv_inst(self, inst, srv_domain):
        """
        Parse a server instance block into name/port/addresses,
        and add them to the services list.

        :param str inst: Server instance block (null-seperated strings)
        :param dnslib.DNSLabel srv_domain: service domain
        """
        name, port, *addresses = inst.split("\0")
        self.services[srv_domain].extend(addresses)

    def run(self):
        """
        Run SCION Dns server.
        """
        self._sync_zk_state()
        self.udp_server.start_thread()
        self.tcp_server.start_thread()
        while self.udp_server.isAlive() and self.tcp_server.isAlive():
            self._sync_zk_state()
            sleep(self.SYNC_TIME)


def main():  # pragma: no cover
    """
    Main function.
    """
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument('server_id', help='Server identifier')
    parser.add_argument('domain', help='DNS Domain')
    parser.add_argument('topology', help='Topology file')
    parser.add_argument('log_file', help='Log file')
    args = parser.parse_args()
    init_logging(args.log_file)

    scion_dns_server = SCIONDnsServer(args.server_id, args.domain,
                                      args.topology)
    scion_dns_server.setup()
    trace(scion_dns_server.id)

    logging.info("Started: %s", datetime.datetime.now())
    scion_dns_server.run()


if __name__ == "__main__":  # pragma: no cover
    try:
        main()
    except SystemExit:
        logging.info("Exiting")
        raise
    except:
        log_exception("Exception in main process:")
        logging.critical("Exiting")
        sys.exit(1)
