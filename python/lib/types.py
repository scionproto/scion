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

    @classmethod
    def all(cls):
        return [getattr(cls, attr) for attr in dir(cls) if
                not attr.startswith("__") and
                not callable(getattr(cls, attr))]


############################
# Basic types
############################
class AddrType(TypeBase):
    NONE = 0
    IPV4 = 1
    IPV6 = 2
    SVC = 3


class ServiceType(TypeBase):
    BS = "bs"
    PS = "ps"
    CS = "cs"
    BR = "br"
    SIBRA = "sb"


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
    ONE_HOP_PATH = 3


class ExtEndToEndType(TypeBase):
    PATH_TRANSPORT = 0
    PATH_PROBE = 1
    SPSE = 2


class ASMExtType(TypeBase):
    ROUTING_POLICY = 0


class RoutingPolType(TypeBase):
    ALLOW_AS = 0
    DENY_AS = 1
    ALLOW_IF = 2
    DENY_IF = 3


class L4Proto(TypeBase):
    NONE = 0
    SCMP = 1
    TCP = 6
    UDP = 17
    L4 = SCMP, TCP, UDP


############################
# Payload class/types
############################
class PayloadClass(object):
    PCB = "pcb"
    IFID = "ifid"
    CERT = "certMgmt"
    PATH = "pathMgmt"
    SIBRA = "sibra"
    DRKEY = "drkeyMgmt"


class CertMgmtType(object):
    CERT_CHAIN_REQ = "certChainReq"
    CERT_CHAIN_REPLY = "certChain"
    TRC_REQ = "trcReq"
    TRC_REPLY = "trc"


class PathMgmtType(object):
    REQUEST = "segReq"
    REPLY = "segReply"
    # Path registration (sent by Beacon Server).
    REG = "segReg"
    # For records synchronization purposes (used by Path Servers).
    SYNC = "segSync"
    REVOCATION = "revInfo"
    IFSTATE_REQ = "ifStateReq"
    IFSTATE_INFOS = "ifStateInfos"


class PathSegmentType(TypeBase):
    """
    PathSegmentType class, indicates a type of path request/reply.
    """
    # XXX(kormat): these strings must match the values in the capnp enum.
    UP = "up"  # Request/Reply for up-paths
    DOWN = "down"  # Request/Reply for down-paths
    CORE = "core"  # Request/Reply for core-paths


class DRKeyMgmtType(object):
    FIRST_ORDER_REQUEST = "drkeyReq"
    FIRST_ORDER_REPLY = "drkeyRep"


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


############################
# Link types
############################
class LinkType(TypeBase):
    #: Link to child AS
    CHILD = "CHILD"
    #: Link to parent AS
    PARENT = "PARENT"
    #: Link to peer AS
    PEER = "PEER"
    #: Link to other core AS
    CORE = "CORE"


###########################
# SCIOND message types
###########################
class SCIONDMsgType(TypeBase):
    UNSET = "unset"
    PATH_REQUEST = "pathReq"
    PATH_REPLY = "pathReply"
    AS_REQUEST = "asInfoReq"
    AS_REPLY = "asInfoReply"
    REVOCATION = "revNotification"
    REVOCATIONREPLY = "revReply"
    IF_REQUEST = "ifInfoRequest"
    IF_REPLY = "ifInfoReply"
    SERVICE_REQUEST = "serviceInfoRequest"
    SERVICE_REPLY = "serviceInfoReply"
    DRKEY_REQUEST = "drkeyRequest"
    DRKEY_REPLY = "drkeyReply"


#######################
# Hash function types
#######################
class HashType(TypeBase):
    SHA256 = 0
