# Copyright 2016 ETH Zurich
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
:mod:`types` --- SCMP types
===========================
All SCMP packets have:

- An extension header, to mark the packet as an SCMP packet, which contains:

  - A hop-by-hop flag, to indicate if routers should process the SCMP payload.
  - An error flag, to indicate if an error while processing this packet should
    generate an SCMP error packet.

- An SCMP l4 header, which contains:

  - Error Class (General/Routing/etc) - a group of error types.
  - Error Type (ECHO_REQUEST/UNREACH_NET/etc).
  - Timestamp of the time the header was created.
  - Length (in bytes) of the SCMP l4 header + SCMP payload.
  - Checksum over pseudoheader, SCMP l4 header and SCMP payload.

- An SCMP payload, which contains:

  - Meta data about the sizes of the various contents of the payload.
  - (For some error class/types) An SCMP Info field, which contains:

    - Any additional information needed to process the payload data.

  - Sections of the original packet's headers, to allow inspection of the
    problem, and also to identify the origin of the packet that caused the
    error. (Except in the case of echo request/reply, where the data here is
    supplied by the application, and is not processed).

All SCMP error packets must contain the following sections of the original
packet (referred to as "basic" below):

- Common header
- Address header
- L4 header, if any

This is to allow the original sender to be identified, and the SCMP error to
be delivered to them.
Some other sections are required, depending on the exact error class/type:

- Path header
- Extension headers

------------
"""
from lib.types import TypeBase


class SCMPClass(TypeBase):
    GENERAL = 0
    ROUTING = 1
    CMNHDR = 2
    PATH = 3
    EXT = 4
    SIBRA = 5


class SCMPGeneralClass(TypeBase):
    """General SCMP errors, and echo request/replies."""
    #: An error which doesn't fall into any existing category. Only to be used
    #: until a more specific error code can be allocated.
    # Info: string describing the error.
    # Payload: all headers.
    UNSPECIFIED = 0
    #: Echo request.
    # Info: Identifier (randomly generated per source app), Sequence Id
    #       (incremented for each packet).
    # Payload: Can be user-supplied. Defaults to sequential byte string.
    ECHO_REQUEST = 1
    #: Echo reply. Same format as Echo request.
    ECHO_REPLY = 2
    ECHO_TRACEROUTE_REQUEST = 3
    ECHO_TRACEROUTE_REPLY = 4
    ECHO_RECORDPATH_REQUEST = 5
    ECHO_RECORDPATH_REPLY = 6


class SCMPRoutingClass(TypeBase):
    """SCMP Routing/delivery errors."""
    #: Destination network unreachable. An L2 error, when there's no route to
    #: the dest host's network.
    # Payload: basic
    UNREACH_NET = 0
    #: Destination host unreachable. An L2 error. E.g. the current machine is on
    #: the same segment as the dest host, and gets no response from it.
    # Payload: basic
    UNREACH_HOST = 1
    #: L2 error not covered by other error types. E.g. TTL exceeded.
    #: FIXME(kormat): Not yet implemented.
    # Info: L2 error code(s)
    # Payload: basic
    L2_ERROR = 2
    #: Destination host does not support the requested l4 protocol.
    # Payload: basic
    UNREACH_PROTO = 3
    #: Destination host unable to parse l4 port number.
    # Payload: basic
    UNREACH_PORT = 4
    #: Destination host unknown. E.g. the dest addr is an SVC address, for which
    #: the router cannot retrieve any service instances.
    # Payload: basic
    UNKNOWN_HOST = 5
    #: Destination host is invalid. E.g. the dest addr is an unsupported SVC
    #: address.
    # Payload: basic
    BAD_HOST = 6
    #: Packet size is larger than MTU.
    # Info: packet size, MTU
    # Payload: basic
    OVERSIZE_PKT = 7
    #: Communication with destination host administratively denied.
    # Payload: basic
    ADMIN_DENIED = 8


class SCMPCmnHdrClass(TypeBase):
    """SCMP Common Header errors."""
    #: Invalid SCION version. E.g. the scion version is deprecated.
    #: N.B. this can only support versions which are known but not allowed, as
    #: otherwise the packet then cannot be processed.
    # Payload: basic
    BAD_VERSION = 0
    #: Invalid destination address type. E.g. the address type is deprecated.
    #: N.B. this can only support versions which are known but not allowed, as
    #: otherwise the packet then cannot be processed.
    # Payload: basic
    BAD_DST_TYPE = 1
    #: Invalid source address type. E.g. the address type is deprecated.
    #: N.B. this can only support versions which are known but not allowed, as
    #: otherwise the packet then cannot be processed.
    # Payload: basic
    BAD_SRC_TYPE = 2
    #: "Total length" field in common header does not match the number of bytes
    #: received.
    # Info: received bytes in packet.
    # Payload: basic
    BAD_PKT_LEN = 3
    #: Invalid IOF offset in common header. E.g. offset is non-zero for an empty
    #: path.
    # Payload: basic
    BAD_IOF_OFFSET = 4
    #: Invalid HOF offset in common header. E.g. offset is non-zero for an empty
    #: path.
    # Payload: basic
    BAD_HOF_OFFSET = 5


class SCMPPathClass(TypeBase):
    """SCMP Path errors."""
    #: Packet cannot be routed as it has no path.
    # Payload: basic.
    PATH_REQUIRED = 0
    #: MAC verification failed.
    # Info: IOF idx, HOF idx
    # Payload: basic, path
    BAD_MAC = 1
    #: HOF expired.
    # Info: IOF idx, HOF idx
    # Payload: basic, path
    EXPIRED_HOF = 2
    #: Invalid interface ID in HOF.
    # Info: IOF idx, HOF idx, ingress flag
    # Payload: basic, path
    BAD_IF = 3
    #: Revoked interface in path
    # Info: IOF idx, HOF idx, ingress flag, revocation info
    # Payload: basic, path
    REVOKED_IF = 4
    #: Current HOF not valid for routing. E.g. HOF has VERIFY_ONLY flag set.
    # Info: IOF idx, HOF idx
    # Payload: basic, path
    NON_ROUTING_HOF = 5
    #: Delivery disallowed by HOF's FORWARD_ONLY flag.
    # Info: IOF idx, HOF idx
    # Payload: basic, path
    DELIVERY_FWD_ONLY = 6
    #: Delivery disallowed as destination is not local.
    # Info: IOF idx, HOF idx
    # Payload: basic, path
    DELIVERY_NON_LOCAL = 7


class SCMPExtClass(TypeBase):
    """SCMP Extension errors."""
    #: Too many hop-by-hop extensions.
    # Info: ext idx
    # Payload: basic, exts
    TOO_MANY_HOPBYHOP = 0
    #: Invalid extension order. E.g. SCMP ext is not first.
    # Info: ext idx
    # Payload: basic, exts
    BAD_EXT_ORDER = 1
    #: Unsupported hop-by-hop extension.
    # Info: ext idx
    # Payload: basic, exts
    BAD_HOPBYHOP = 2
    #: Unsupported end-to-end extension.
    # Info: ext idx
    # Payload: basic, exts
    BAD_END2END = 3


class SCMPSibraClass(TypeBase):
    """SIBRA errors."""
    #: Unsupported SIBRA version
    # Payload: basic, sibra ext header
    BAD_VERSION = 0
    #: Request flag not set in setup packet
    # Payload: basic, sibra ext header
    SETUP_NO_REQ = 1


class SCMPIncParts(TypeBase):
    CMN = 0
    ADDRS = 1
    PATH = 2
    EXTS = 3
    L4 = 4


class SCMPInfoType(TypeBase):
    STRING = 0
    ECHO = 1
    PKT_SIZE = 2
    PATH_OFFSETS = 3
    REVOCATION = 4
    EXT_IDX = 5
