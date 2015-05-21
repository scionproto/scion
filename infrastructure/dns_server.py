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
import binascii
import datetime
import logging
import os
import sys
import threading
import time
from ipaddress import ip_address

# External packages
from dnslib import A, AAAA, DNSLabel, PTR, QTYPE, RCODE, RR, SRV
from dnslib.server import (
    BaseResolver,
    DNSLogger,
    DNSServer,
    TCPServer,
    UDPServer,
)
from kazoo.exceptions import (
    ConnectionLoss,
    SessionExpiredError,
)

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.defines import SCION_DNS_PORT
from lib.log import init_logging, log_exception
from lib.thread import kill_self
from lib.util import handle_signals, trace
from lib.zookeeper import ZkConnectionLoss, Zookeeper

#: IPv4 reverse lookup domain
V4REV = DNSLabel("in-addr.arpa")
#: IPv6 reverse lookup domain
V6REV = DNSLabel("ip6.arpa")


class SrvInst(object):
    """
    Represents a service instance.
    """
    def __init__(self, data, domain):
        """
        Parse a service instances's details from a ZK party entry.

        :param bytes data: ZK party entry - service name/port/IPs delimited with
                           nul bytes.
        :param dnslib.DNSLabel domain: The parent DNS domain.
        """
        name, port, *addresses = data.split("\0")
        self.id = DNSLabel(name)
        self.domain = domain
        self.fqdn = self.domain.add(self.id)
        self.port = int(port)
        self.v4_addrs = []
        self.v6_addrs = []
        for addr in addresses:
            ip = ip_address(addr)
            if ip.version == 4:
                self.v4_addrs.append(ip)
            elif ip.version == 6:
                self.v6_addrs.append(ip)

    def reverse_pointers(self):
        """
        Generate the reverse DNS labels for the instances's IP addresses (for
        both IPv4 and IPv6)

        :return: List of reverse DNS labels. E.g.
                 ``["3.0.0.127.in-addr.arpa."]``
        """
        # http://stackoverflow.com/a/30007941
        answer = []
        for addr in self.v4_addrs:
            reverse_octets = addr.exploded.split(".")[::-1]
            answer.append(V4REV.add(".".join(reverse_octets)))
        for addr in self.v6_addrs:
            reverse_chars = addr.exploded[::-1].replace(":", "")
            answer.append(V6REV.add(".".join(reverse_chars)))
        return answer

    def service_records(self, qtype, reply):
        """
        Generate DNS records for a service.

        :param str qtype: Query type (e.g. ``"AAAA"``).
        :param dnslib.DNSRecord reply: DNSRecord object to add the replies to.
        """
        # 'answer' section
        if qtype in ["A", "ANY"]:
            for addr in self.v4_addrs:
                reply.add_answer(RR(self.domain, QTYPE.A, rdata=A(str(addr))))
        if qtype in ["AAAA", "ANY"]:
            for addr in self.v6_addrs:
                reply.add_answer(RR(self.domain, QTYPE.AAAA,
                                    rdata=AAAA(str(addr))))
        # Always return SRV records in 'answer' section
        reply.add_answer(RR(self.domain, QTYPE.SRV, rdata=SRV(target=self.fqdn,
                                                              port=self.port)))
        # Add instance A/AAAA records to 'additional' response section
        for addr in self.v4_addrs:
            reply.add_ar(RR(self.fqdn, QTYPE.A, rdata=A(str(addr))))
        for addr in self.v6_addrs:
            reply.add_ar(RR(self.fqdn, QTYPE.AAAA, rdata=AAAA(str(addr))))

    def instance_records(self, qtype, reply):
        """
        Generate DNS records for this instance specifically.

        :param str qtype: Query type (e.g. ``"AAAA"``).
        :param dnslib.DNSRecord reply: DNSRecord object to add the replies to.
        """
        # 'answer' section
        if qtype in ["A", "ANY"]:
            for addr in self.v4_addrs:
                reply.add_answer(RR(self.fqdn, QTYPE.A, rdata=A(str(addr))))
        if qtype in ["AAAA", "ANY"]:
            for addr in self.v6_addrs:
                reply.add_answer(RR(self.fqdn, QTYPE.AAAA,
                                    rdata=AAAA(str(addr))))
        # Always return SRV records in 'answer' section
        reply.add_answer(RR(self.fqdn, QTYPE.SRV, rdata=SRV(target=self.fqdn,
                                                            port=self.port)))
        # Add instance A/AAAA records to 'additional' response section if not
        # already in the 'answer' section
        if qtype not in ["A", "ANY"]:
            for addr in self.v4_addrs:
                reply.add_ar(RR(self.fqdn, QTYPE.A, rdata=A(str(addr))))
        if qtype not in ["AAAA", "ANY"]:
            for addr in self.v6_addrs:
                reply.add_ar(RR(self.fqdn, QTYPE.AAAA, rdata=AAAA(str(addr))))

    def reverse_record(self, qname, reply):
        """
        Generate a DNS PTR record for this instance.

        :param dnslib.DNSLabel qname: The requested PTR record name.
        :param dnslib.DNSRecord reply: DNSRecord object to add the replies to.
        """
        reply.add_answer(RR(qname, QTYPE.PTR, rdata=PTR(label=self.fqdn)))

    def __repr__(self):
        ips = []
        for addr in self.v4_addrs:
            ips.append(str(addr))
        for addr in self.v6_addrs:
            ips.append(str(addr))
        return "<SrvInst id: %s port: %s IPs: %s>" % (self.fqdn, self.port,
                                                      ",".join(ips))


class ZoneResolver(BaseResolver):
    """
    Handle DNS queries.
    """
    def __init__(self, lock, domain, srv_types):
        """
        :param threading.Lock lock: Lock to coordinate access to instance data.
        :param dnslib.Domain domain: Parent DNS domain.
        :param [`str`] srv_types: List of supported service types. E.g.
                                  ``["bs", "cs"]``
        """
        self.srv_types = srv_types
        self.services = {}
        self.instances = {}
        self.reverse = {}
        self.lock = lock
        self.domain = domain

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

        if qtype in ["A", "AAAA", "ANY", "SRV"]:
            self.resolve_forward(qname, qtype, reply)
        elif qtype == "PTR":
            self.resolve_reverse(qname, reply)
        else:
            # Not a request type we support
            logging.warning("Unsupported query type: %s", qtype)
            reply.header.rcode = RCODE.NXDOMAIN
        return reply

    def resolve_forward(self, qname, qtype, reply):
        """
        Build a response to a forward DNS query (i.e. one that contains a
        hostname)

        :param dnslib.DNSLabel qname: The query's target.
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
            for srv_domain, srv_insts in self.services.items():
                if qname.matchSuffix(srv_domain):
                    if not srv_insts:
                        # If there are no instances, we are unable to read from
                        # ZK (or else the relevant service is down), so return
                        # SERVFAIL
                        reply.header.rcode = RCODE.SERVFAIL
                        return
                    for inst in srv_insts:
                        inst.service_records(qtype, reply)
                    return
            # Or is it for an instance?
            inst = self.instances.get(qname)
            if inst:
                inst.instance_records(qtype, reply)
                return
            logging.warning("Unknown service/instance: %s", qname)
            reply.header.rcode = RCODE.NXDOMAIN
            return

    def resolve_reverse(self, qname, reply):
        """
        Build a response to a reverse DNS query (i.e. one that contains an IP
        address)

        :param dnslib.DNSLabel qname: The query's target.
        :param dnslib.DNSRecord reply: The DNSRecord to populate with the reply.
        """
        with self.lock:
            if qname in self.reverse:
                self.reverse[qname].reverse_record(qname, reply)
            else:
                logging.warning("Unknown reverse record: %s", qname)
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


class SCIONDnsLogger(DNSLogger):
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
        return "[%s:%d] (%s)" % (
            handler.client_address[0],
            handler.client_address[1],
            handler.protocol)

    def _reply_prefix(self, handler, reply, desc):
        return "%s: %s / '%s' (%s) /" % (
            desc,
            self._common_prefix(handler, reply),
            reply.q.qname,
            QTYPE[reply.q.qtype])

    def _format_rrs(self, reply):
        return "RRs: %s" % ",".join([QTYPE[a.rtype] for a in reply.rr])

    def log_recv(self, handler, data):
        logging.log(self.level, "Received: %s <%d> : %s",
                    self._common_prefix(handler, data),
                    len(data),
                    binascii.hexlify(data))

    def log_send(self, handler, data):
        logging.log(self.level, "Sent: %s <%d> : %s",
                    self._common_prefix(handler, data),
                    len(data),
                    binascii.hexlify(data))

    def log_request(self, handler, request):
        logging.log(self.level, "Request: %s / '%s' (%s)",
                    self._common_prefix(handler, request),
                    request.q.qname,
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
                    self._common_prefix(handler, e),
                    e)

    def log_data(self, dnsobj):
        for line in dnsobj.toZone("    ").split("\n"):
            logging.log(self.level, line)


class SCIONDnsServer(SCIONElement):
    """
    SCION DNS Server. Responsible for starting the DNS resolver threads, and
    frequently updating the shared instance data from ZK.
    """
    #: How frequently (in seconds) to update the shared instance data from ZK.
    SYNC_TIME = 1.0
    #: Service types to monitor/export
    SRV_TYPES = ["bs", "cs", "ds", "ps"]

    def __init__(self, server_id, domain, topo_file):
        super().__init__("ds", topo_file, server_id=server_id)
        self.domain = DNSLabel(domain)
        self.lock = threading.Lock()
        self.resolver = ZoneResolver(self.lock, self.domain, self.SRV_TYPES)
        self.udp_server = DNSServer(self.resolver, port=SCION_DNS_PORT,
                                    address=str(self.addr.host_addr),
                                    server=SCIONDnsUdpServer,
                                    logger=SCIONDnsLogger())
        self.tcp_server = DNSServer(self.resolver, port=SCION_DNS_PORT,
                                    address=str(self.addr.host_addr),
                                    server=SCIONDnsTcpServer,
                                    logger=SCIONDnsLogger())
        self.zk = Zookeeper(
            self.topology.isd_id, self.topology.ad_id,
            "ds", self.addr.host_addr, ["localhost:2181"])
        self.name_addrs = "\0".join([self.id, str(SCION_DNS_PORT),
                                     str(self.addr.host_addr)])
        self._parties = {}
        self._join_parties()

    def _join_parties(self):
        while True:
            logging.debug("Waiting for ZK connection")
            if not self.zk.wait_connected(timeout=10.0):
                continue
            logging.debug("Connected to ZK")
            try:
                for i in self.SRV_TYPES:
                    self._parties[i] = self._join_party(i)
                # Join the DNS server party
                self._parties['ds'].join()
            except ZkConnectionLoss:
                logging.info("Connection dropped while "
                             "registering for parties")
                continue
            else:
                break
        self._sync_zk_state()

    def _join_party(self, type_):
        prefix = "/ISD%d-AD%d" % (self.topology.isd_id, self.topology.ad_id)
        path = os.path.join(prefix, type_, 'party')
        self.zk._zk.ensure_path(path)
        return self.zk._zk.Party(path, self.name_addrs)

    def _sync_zk_state(self):
        """
        Update shared instance data from ZK.
        """
        services = {}
        instances = {}
        reverse = {}

        # Retrieve alive instance details from ZK for each service.
        for srv_type in self.SRV_TYPES:
            srv_domain = self.domain.add(srv_type)
            services[srv_domain] = []
            try:
                srv_set = set(self._parties[srv_type])
            except (ConnectionLoss, SessionExpiredError):
                # If the connection drops, leave the instance list blank
                continue
            for i in srv_set:
                new_inst = SrvInst(i, self.domain)
                instances[new_inst.fqdn] = new_inst
                services[srv_domain].append(new_inst)
                # Build reverse lookup table
                for rev in new_inst.reverse_pointers():
                    reverse[rev] = new_inst
        old_names = set(self._instance_names(self.resolver.instances))
        new_names = set(self._instance_names(instances))

        # Update DNS zone data
        with self.lock:
            self.resolver.services = services
            self.resolver.instances = instances
            self.resolver.reverse = reverse

        # Calculate additions/removals
        added = new_names - old_names
        if added:
            logging.info("Added instance(s): %s", ",".join(sorted(added)))
        removed = old_names - new_names
        if removed:
            logging.info("Removed instance(s): %s", ",".join(sorted(removed)))

    def _instance_names(self, instances):
        return [str(inst.id).rstrip(".") for inst in instances.values()]

    def run(self):
        self.udp_server.start_thread()
        self.tcp_server.start_thread()
        while self.udp_server.isAlive() and self.tcp_server.isAlive():
            self._sync_zk_state()
            time.sleep(self.SYNC_TIME)


def main():
    """
    Main function.
    """
    init_logging()
    handle_signals()
    if len(sys.argv) != 4:
        logging.error("run: %s server_id domain topo_file", sys.argv[0])
        sys.exit()

    scion_dns_server = SCIONDnsServer(*sys.argv[1:])
    trace(scion_dns_server.id)

    logging.info("Started: %s", datetime.datetime.now())
    scion_dns_server.run()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        logging.info("Exiting")
        raise
    except:
        log_exception("Exception in main process:")
        logging.critical("Exiting")
        sys.exit(1)
