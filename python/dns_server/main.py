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
:mod:`main` --- SCION DNS server
================================
This is a custom DNS server, built on Paul Chakravarti's `dnslib
<https://bitbucket.org/paulc/dnslib>`_.

It dynamically provides DNS records for the AS based on service instances
registering in Zookeeper.
"""
# Stdlib
import logging
import threading
from time import sleep

# External packages
from dnslib import DNSLabel
from dnslib.server import DNSServer

# SCION
from dns_server.logger import SCIONDnsLogger
from dns_server.resolver import ZoneResolver
from dns_server.servers import (
    SCIONDnsTcpServer,
    SCIONDnsUdpServer,
)
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    DNS_SERVICE,
    PATH_SERVICE,
    SCION_DNS_PORT,
    SIBRA_SERVICE,
)
from lib.zk.errors import ZkNoConnection
from lib.zk.zk import Zookeeper
from scion_elem.scion_elem import SCIONElement


class SCIONDnsServer(SCIONElement):
    """
    SCION DNS Server. Responsible for starting the DNS resolver threads, and
    frequently updating the shared instance data from ZK.

    :cvar float SYNC_TIME: How frequently (in seconds) to update the shared
                           instance data from ZK.
    :cvar list SRV_TYPES: Service types to monitor/export
    """
    SERVICE_TYPE = DNS_SERVICE
    SYNC_TIME = 1.0
    SRV_TYPES = (BEACON_SERVICE, CERTIFICATE_SERVICE,
                 DNS_SERVICE, PATH_SERVICE, SIBRA_SERVICE)

    def __init__(self, server_id, conf_dir, setup=False, prom_export=None):  # pragma: no cover
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param str prom_export: prometheus export address.
        :param bool setup: should setup() be called?
        """
        super().__init__(server_id, conf_dir, prom_export=prom_export)
        self.domain = DNSLabel(self.topology.dns_domain)
        self.lock = threading.Lock()
        self.services = {}
        if setup:
            self.setup()

    def setup(self):
        """
        Set up various servers and connections required.
        """
        self.resolver = ZoneResolver(self.lock, self.domain)
        self.udp_server = DNSServer(self.resolver, port=SCION_DNS_PORT,
                                    address=str(self.addr.host),
                                    server=SCIONDnsUdpServer,
                                    logger=SCIONDnsLogger())
        self.tcp_server = DNSServer(self.resolver, port=SCION_DNS_PORT,
                                    address=str(self.addr.host),
                                    server=SCIONDnsTcpServer,
                                    logger=SCIONDnsLogger())
        self.name_addrs = "\0".join([self.id, str(SCION_DNS_PORT),
                                     str(self.addr.host)])
        self.zk = Zookeeper(self.topology.isd_as, DNS_SERVICE, self.name_addrs,
                            self.topology.zookeepers)
        self._parties = {}
        self._setup_parties()

    def _setup_parties(self):
        """
        Join all the necessary ZK parties.
        """
        logging.debug("Joining parties")
        for type_ in self.SRV_TYPES:
            prefix = "/%s/%s" % (self.addr.isd_as, type_)
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
        except ZkNoConnection:
            logging.warning("No connection to Zookeeper, can't update services")
            return

        # Retrieve alive instance details from ZK for each service.
        for srv_type in self.SRV_TYPES:
            srv_domain = self.domain.add(srv_type)
            self.services[srv_domain] = []
            party = self._parties[srv_type]
            try:
                srvs = party.list()
            except ZkNoConnection:
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

    def handle_request(self, packet, sender, from_local_socket=True):
        raise NotImplementedError

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
