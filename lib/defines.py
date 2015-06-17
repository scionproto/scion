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

#: Default value for lenght (in bytes) of cryptographic hash
HASH_LEN = 32
