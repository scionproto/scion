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
    def to_str(cls, type_):
        for attr in dir(cls):
            if getattr(cls, attr) == type_:
                return attr
        return "UNKNOWN"


############################
# Basic types
############################
class AddrType(TypeBase):
    NONE = 0
    IPV4 = 1
    IPV6 = 2
    SVC = 3


class ExtensionClass(TypeBase):
    """
    Constants for two types of extensions. These values are shared with L4
    protocol values, and an appropriate value is placed in next_hdr type.
    """
    HOP_BY_HOP = 0
    END_TO_END = 222  # (Expected:-) number for SCION end2end extensions.


class OpaqueFieldType(TypeBase):
    """
    Constants for the types of the opaque field (first byte of every opaque
    field).
    """
    # Types for HopOpaqueFields (7 MSB bits).
    NORMAL_OF = 0b0000000
    XOVR_POINT = 0b0010000  # Indicates a crossover point.
    # Types for Info Opaque Fields (7 MSB bits).
    CORE = 0b1000000
    SHORTCUT = 0b1100000
    INTRA_ISD_PEER = 0b1111000
    INTER_ISD_PEER = 0b1111100


############################
# Payload class/types
############################
class PayloadClass(TypeBase):
    PCB = 0
    IFID = 1
    CERT = 2
    PATH = 3


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
