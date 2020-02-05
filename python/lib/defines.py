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

#: SCION protocol version
SCION_PROTO_VERSION = 0

#: Default TTL of a PathSegment in realtime seconds.
DEFAULT_SEGMENT_TTL = 6 * 60 * 60
#: Max TTL of a PathSegment in realtime seconds.
MAX_SEGMENT_TTL = 24 * 60 * 60
#: Time unit for HOF expiration.
EXP_TIME_UNIT = int(MAX_SEGMENT_TTL / 2 ** 8)
#: Max number of supported HopByHop extensions (does not include SCMP)
MAX_HOPBYHOP_EXT = 3
#: Number of bytes per 'line'. Used for padding in many places.
LINE_LEN = 8

#: Generated files directory
GEN_PATH = 'gen'
#: Topology configuration
TOPO_FILE = "topology.json"
#: Networks config
NETWORKS_FILE = "networks.conf"
#: IFIDs list
IFIDS_FILE = "ifids.yml"
#: AS list
AS_LIST_FILE = "as_list.yml"
#: Prometheus config
PROM_FILE = "prometheus.yml"

#: Buffer size for receiving packets
SCION_BUFLEN = 65535
#: Default SCION endhost data port
SCION_UDP_EH_DATA_PORT = 30041
#: Default SCION router UDP port.
SCION_ROUTER_PORT = 50000
#: Default SCION dispatcher UNIX socket directory
DISPATCHER_DIR = "/run/shm/dispatcher"
#: Default SCION dispatcher ID
DEFAULT_DISPATCHER_ID = "default"

#: Dispatcher registration timeout
DISPATCHER_TIMEOUT = 60.0

#: Default MTU - assumes overlay is ipv4+udp
DEFAULT_MTU = 1500 - 20 - 8
#: IPv6 min value
SCION_MIN_MTU = 1280
#: Length of opaque fields
OPAQUE_FIELD_LEN = 8

PATH_FLAG_CACHEONLY = "CACHE_ONLY"

# Minimum revocation TTL in seconds
MIN_REVOCATION_TTL = 10
REVOCATION_GRACE = 1

# Default IPv6 network, our equivalent to 127.0.0.0/8
# https://en.wikipedia.org/wiki/Unique_local_address#Definition
DEFAULT6_MASK = "/104"
DEFAULT6_NETWORK_ADDR = "fd00:f00d:cafe::7f00:0000"
DEFAULT6_NETWORK = DEFAULT6_NETWORK_ADDR + DEFAULT6_MASK
DEFAULT6_PRIV_NETWORK_ADDR = "fd00:f00d:cafe::c000:0000"
DEFAULT6_PRIV_NETWORK = DEFAULT6_PRIV_NETWORK_ADDR + DEFAULT6_MASK
DEFAULT6_CLIENT = "fd00:f00d:cafe::7f00:0002"
DEFAULT6_SERVER = "fd00:f00d:cafe::7f00:0003"

DOCKER_COMPOSE_CONFIG_VERSION = "2.4"
