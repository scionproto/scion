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
:mod:`types` --- SCION types
============================

For all type classes that are used in multiple parts of the infrastructure.
"""


class TypeBase(object):  # pragma: no cover
    @classmethod
    def to_str(cls, type_, error=False):
        for attr in dir(cls):
            if getattr(cls, attr) == type_:
                return attr
        if not error:
            return "UNKNOWN (%s)" % type_
        raise IndexError


############################
# Basic types
############################
class AddrType(TypeBase):
    NONE = 0
    IPV4 = 1
    IPV6 = 2
    SVC = 3
    UNIX = 4  # For dispatcher socket


class ExtensionClass(TypeBase):
    """
    Constants for two types of extensions. These values are shared with L4
    protocol values, and an appropriate value is placed in next_hdr type.
    """
    HOP_BY_HOP = 0
    END_TO_END = 222  # (Expected:-) number for SCION end2end extensions.


class ExtHopByHopType(TypeBase):
    TRACEROUTE = 0
    SIBRA = 1
    SCMP = 2


class ExtEndToEndType(TypeBase):
    PATH_TRANSPORT = 0
    PATH_PROBE = 1


class L4Proto(TypeBase):
    NONE = 0
    SCMP = 1
    TCP = 6
    UDP = 17
    SSP = 152
    L4 = SCMP, TCP, UDP, SSP


############################
# Payload class/types
############################
class PayloadClass(TypeBase):
    PCB = 0
    IFID = 1
    CERT = 2
    PATH = 3
    SIBRA = 4


class CertMgmtType(TypeBase):
    CERT_CHAIN_REQ = 0
    CERT_CHAIN_REPLY = 1
    TRC_REQ = 2
    TRC_REPLY = 3


class PathMgmtType(TypeBase):
    """
    Enum of path management packet types.
    """
    REQUEST = 0
    REPLY = 1
    REG = 2  # Path registration (sent by Beacon Server).
    SYNC = 3  # For records synchronization purposes (used by Path Servers).
    REVOCATION = 4
    IFSTATE_INFO = 5
    IFSTATE_REQ = 6


class PathSegmentType(TypeBase):
    """
    PathSegmentType class, indicates a type of path request/reply.
    """
    UP = 0  # Request/Reply for up-paths
    DOWN = 1  # Request/Reply for down-paths
    CORE = 2  # Request/Reply for core-paths
    GENERIC = 3  # FIXME(PSz): experimental for now.


class PCBType(TypeBase):
    SEGMENT = 0


class IFIDType(object):
    PAYLOAD = 0


class SIBRAPayloadType(TypeBase):
    EMPTY = 0


############################
# Router types
############################
class RouterFlag(TypeBase):
    ERROR = 0
    NO_PROCESS = 1
    # Process this locally
    PROCESS_LOCAL = 2
    # Forward packet to supplied IFID
    FORWARD = 3
    # Packet has reached its destination ISD-AS
    DELIVER = 4
    # Deliver packet even if it hasn't reached its destination ISD-AS
    FORCE_DELIVER = 5


############################
# SIBRA types
############################
class SIBRAPathType(TypeBase):
    STEADY = 0
    EPHEMERAL = 1
