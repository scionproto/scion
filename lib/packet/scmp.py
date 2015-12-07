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
:mod:`scmp` --- SCION ICMP
==========================
"""
# Stdlib

# External

# SCION
from lib.packet.packet_base import HeaderBase, PacketBase


class SCMPType(object):
    """
    SCMP types.

    This class contains a list of constants representing the current SCMP
    types. The set of types is loosely based on the ICMP types. At the moment
    only the currently-supported types are included.
    """

    ECHO_REPLY = 0
    # TODO: Add support for following constants in the near future
    #DEST_UNREACHABLE = 1
    #INVALID_PATH = 2


class SCMPHeader(HeaderBase):
    """
    Packet header for SCMP messages.
    """

    def __init__(self, raw=None):
        pass

    def _parse(self, raw):
        pass

    def from_values(self, *args, **kwargs):
        pass

    def pack(self):
        pass

    def __len__(self):
        pass

    def __str__(self):
        pass


class SCMPPacket(PacketBase):
    """
    Packet format for SCMP messages.
    """

    def __init__(self, raw=None):
        pass

    def _parse(self, raw):
        pass

    def from_values(self, *args, **kwargs):
        pass

    def pack(self):
        pass

    def __len__(self):
        pass

    def __str__(self):
        pass
