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
:mod:`errors` --- SCMP Errors
=============================
For descriptions of the errors, refer to lib.packet.scmp.types
"""

# SCION
from lib.errors import SCIONBaseError
from lib.packet.scmp.types import (
    SCMPClass,
    SCMPCmnHdrClass,
    SCMPExtClass,
    SCMPGeneralClass,
    SCMPPathClass,
    SCMPRoutingClass,
)


class SCMPError(SCIONBaseError):
    """Base exception for all SCMP errors."""
    INFO = None


############################
# General errors
############################
class SCMPGeneralError(SCMPError):
    """Base exception for all SCMP General class errors."""
    CLASS = SCMPClass.GENERAL


class SCMPUnspecified(SCMPGeneralError):
    """Generic error, only to be used until a more specific error is added."""
    TYPE = SCMPGeneralClass.UNSPECIFIED


############################
# Routing errors
############################
class SCMPRoutingError(SCMPError):
    """Base exception for all SCMP Routing class errors."""
    CLASS = SCMPClass.ROUTING


class SCMPUnreachNet(SCMPRoutingError):
    TYPE = SCMPRoutingClass.UNREACH_NET


class SCMPUnreachHost(SCMPRoutingError):
    TYPE = SCMPRoutingClass.UNREACH_HOST


class SCMPL2Error(SCMPRoutingError):
    TYPE = SCMPRoutingClass.L2_ERROR


class SCMPUnreachProto(SCMPRoutingError):
    TYPE = SCMPRoutingClass.UNREACH_PROTO


class SCMPUnreachPort(SCMPRoutingError):
    TYPE = SCMPRoutingClass.UNREACH_PORT


class SCMPUnknownHost(SCMPRoutingError):
    TYPE = SCMPRoutingClass.UNKNOWN_HOST


class SCMPBadHost(SCMPRoutingError):
    TYPE = SCMPRoutingClass.BAD_HOST


class SCMPOversizePkt(SCMPRoutingError):
    TYPE = SCMPRoutingClass.OVERSIZE_PKT


class SCMPAdminDenied(SCMPRoutingError):
    TYPE = SCMPRoutingClass.ADMIN_DENIED


############################
# Common Header errors
############################
class SCMPCmnHdrError(SCMPError):
    """Base exception for all SCMP Common Header class errors."""
    CLASS = SCMPClass.CMNHDR


class SCMPBadVersion(SCMPCmnHdrError):
    TYPE = SCMPCmnHdrClass.BAD_VERSION


class SCMPBadSrcType(SCMPCmnHdrError):
    TYPE = SCMPCmnHdrClass.BAD_SRC_TYPE


class SCMPBadDstType(SCMPCmnHdrError):
    TYPE = SCMPCmnHdrClass.BAD_DST_TYPE


class SCMPBadPktLen(SCMPCmnHdrError):
    TYPE = SCMPCmnHdrClass.BAD_PKT_LEN


class SCMPBadIOFOffset(SCMPCmnHdrError):
    TYPE = SCMPCmnHdrClass.BAD_IOF_OFFSET


class SCMPBadHOFOffset(SCMPCmnHdrError):
    TYPE = SCMPCmnHdrClass.BAD_HOF_OFFSET


############################
# Path errors
############################
class SCMPPathError(SCMPError):
    """Base exception for all SCMP Path class errors."""
    CLASS = SCMPClass.PATH


class SCMPPathRequired(SCMPPathError):
    TYPE = SCMPPathClass.PATH_REQUIRED


class SCMPBadMAC(SCMPPathError):
    TYPE = SCMPPathClass.BAD_MAC


class SCMPExpiredHOF(SCMPPathError):
    TYPE = SCMPPathClass.EXPIRED_HOF


class SCMPBadIF(SCMPPathError):
    TYPE = SCMPPathClass.BAD_IF


class SCMPRevokedIF(SCMPPathError):
    TYPE = SCMPPathClass.REVOKED_IF


class SCMPNonRoutingHOF(SCMPPathError):
    TYPE = SCMPPathClass.NON_ROUTING_HOF


class SCMPDeliveryNonLocal(SCMPPathError):
    TYPE = SCMPPathClass.DELIVERY_NON_LOCAL


############################
# Extension errors
############################
class SCMPExtError(SCMPError):
    """Base exception for all SCMP Ext class errors."""
    CLASS = SCMPClass.EXT


class SCMPTooManyHopByHop(SCMPExtError):
    TYPE = SCMPExtClass.TOO_MANY_HOPBYHOP


class SCMPBadExtOrder(SCMPExtError):
    TYPE = SCMPExtClass.BAD_EXT_ORDER


class SCMPBadHopByHop(SCMPExtError):
    TYPE = SCMPExtClass.BAD_HOPBYHOP


class SCMPBadEnd2End(SCMPExtError):
    TYPE = SCMPExtClass.BAD_END2END
