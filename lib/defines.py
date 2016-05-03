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

#: SCION protocol version
SCION_PROTO_VERSION = 0

#: Max TTL of a PathSegment in realtime seconds.
MAX_SEGMENT_TTL = 24 * 60 * 60
#: Time unit for HOF expiration.
EXP_TIME_UNIT = MAX_SEGMENT_TTL / 2 ** 8
#: Max number of supported HopByHop extensions (does not include SCMP)
MAX_HOPBYHOP_EXT = 3
#: Number of bytes per 'line'. Used for padding in many places.
LINE_LEN = 8

#: Base path of project
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#: Generated files directory
GEN_PATH = 'gen'
#: Topology configuration
TOPO_FILE = "topology.yml"
#: AS configuration
AS_CONF_FILE = "as.yml"
#: Path policy config
PATH_POLICY_FILE = "path_policy.yml"
#: Networks config
NETWORKS_FILE = "networks.conf"
#: AS list
AS_LIST_FILE = "as_list.yml"

#: Buffer size for receiving packets
SCION_BUFLEN = 65535
#: Default SCION server data port
SCION_UDP_PORT = 30040
#: Default SCION endhost data port
SCION_UDP_EH_DATA_PORT = 30041
#: Default DNS UDP/TCP port
SCION_DNS_PORT = 30053
#: Default SCION router UDP port.
SCION_ROUTER_PORT = 50000
#: Default SCION dispatcher host addr
SCION_DISPATCHER_ADDR = "/run/shm/dispatcher.socket"
#: Default SCION dispatcher port
SCION_DISPATCHER_PORT = 3334

BEACON_SERVICE = "bs"
CERTIFICATE_SERVICE = "cs"
DNS_SERVICE = "ds"
PATH_SERVICE = "ps"
ROUTER_SERVICE = "er"
SIBRA_SERVICE = "sb"
#: All the service types
SERVICE_TYPES = (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    DNS_SERVICE,
    PATH_SERVICE,
    ROUTER_SERVICE,
    SIBRA_SERVICE,
)

#: Dispatcher registration timeout
DISPATCHER_TIMEOUT = 60.0

#: How often IFID packet is sent to neighboring router.
IFID_PKT_TOUT = 1
#: Default MTU
DEFAULT_MTU = 1500
#: IPv6 min value
SCION_MIN_MTU = 1280
#: Length of opaque fields
OPAQUE_FIELD_LEN = 8
#: How long certain warnings should be suppresed after startup
STARTUP_QUIET_PERIOD = 30

#: Number of seconds per sibra tick
SIBRA_TICK = 4
#: How far in the future a steady path can reserve at a time.
SIBRA_MAX_STEADY_TICKS = 45
#: How far in the future an ephemeral path can reserve at a time.
SIBRA_MAX_EPHEMERAL_TICKS = 4
#: Length of steady path ID in bytes
SIBRA_STEADY_ID_LEN = 8
#: Length of ephemeral path ID in bytes
SIBRA_EPHEMERAL_ID_LEN = 16
#: SIBRA Bandwidth multiplier
SIBRA_BW_FACTOR = 16 * 1024
#: SIBRA max reservation index
SIBRA_MAX_IDX = 16
