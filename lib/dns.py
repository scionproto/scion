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
:mod:`lib.dns` --- SCION DNS library
====================================
"""
# Stdlib
import socket

# External packages
from dnslib import DNSRecord, QTYPE

# SCION
from lib.defines import SCION_DNS_PORT


def get_hosts_by_srvname(service_name, dns_ip, dns_port=SCION_DNS_PORT,
                         timeout=2):
    """
    Return list of alive instances for given service name, or None when DNS
    query fails

    :param service_name:
    :type service_name:
    :param dns_ip:
    :type dns_ip:
    :param dns_port:
    :type dns_port:
    :param timeout:
    :type timeout:

    :returns: alive instances for a given service name.
    :rtype: list
    """
    # FIXME(kormat): this function isn't finished/tested/anything.
    q = DNSRecord.question(service_name, "ANY")
    try:
        reply_pkt = q.send(dns_ip, dns_port, timeout=timeout)
    except socket.timeout:
        return None  # DNS query failed
    reply = DNSRecord.parse(reply_pkt)
    hosts = []
    if reply and reply.rr:
        for rr in reply.rr:
            if rr.rtype == QTYPE.A:
                hosts.append(str(rr.rdata))
    return hosts
