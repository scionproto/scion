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
:mod:`defines` --- Constants
============================
Contains constant definitions used throughout the codebase.
"""
# Stdlib
import os

#: Max TTL of a PathSegment in realtime seconds.
MAX_SEGMENT_TTL = 24 * 60 * 60
#: Time unit for HOF expiration.
EXP_TIME_UNIT = MAX_SEGMENT_TTL / 2 ** 8

#: Base path of project
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#: Topology subdir path
TOPOLOGY_PATH = os.path.join(PROJECT_ROOT, 'topology')

#: Buffer size for receiving packets
SCION_BUFLEN = 8092
#: Default SCION server data port
SCION_UDP_PORT = 30040
#: Default SCION endhost data port
SCION_UDP_EH_DATA_PORT = 30041
#: Default DNS UDP/TCP port
SCION_DNS_PORT = 30053
#: Default SCION router UDP port.
SCION_ROUTER_PORT=50000

#: (Pseudo)supported layer-4 protocols, see /etc/protocols for details
L4_ICMP = 1
L4_TCP = 6
L4_UDP = 17
L4_RESERVED = 255
L4_PROTOS = [L4_ICMP, L4_TCP, L4_UDP, L4_RESERVED]
#: Default layer-4 protocol.
L4_DEFAULT = L4_RESERVED

BEACON_SERVICE = "bs"
CERTIFICATE_SERVICE = "cs"
DNS_SERVICE = "ds"
PATH_SERVICE = "ps"
ROUTER_SERVICE = "er"
#: All the service types
SERVICE_TYPES = (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    DNS_SERVICE,
    PATH_SERVICE,
    ROUTER_SERVICE,
)

#: How often IFID packet is sent to neighboring router.
IFID_PKT_TOUT = 1

#: Null address type
ADDR_NONE_TYPE = 0
#: IPv4 address type
ADDR_IPV4_TYPE = 1
#: IPv6 address type
ADDR_IPV6_TYPE = 2
#: SCION Service address type
ADDR_SVC_TYPE = 3
