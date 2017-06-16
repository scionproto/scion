# Copyright 2017 ETH Zurich
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
:mod:`misc` --- SCION DRKey misc for OPT
=====================================================
"""

# External
import capnp  # noqa

# SCION
import proto.drkey_mgmt_capnp as P

from lib.drkey.types import DRKeyMiscBase
from lib.packet.scion_addr import ISD_AS


class OPTMiscRequest(DRKeyMiscBase):
    NAME = "OPTMiscRequest"
    P_CLS = P.MiscOPTReq

    def __init__(self, p):
        super().__init__(p)
        self.path = []
        for isd_as in p.path:
            self.path.append(ISD_AS(isd_as))

    @classmethod
    def from_values(cls, session_id, path=None):
        """
        Create OPTMiscRequest from values.
        Path[0] = source AS. Path[-1] = destination AS.

        :param bytes session_id: session identifier (16B)
        :param [ISD_AS] path: list of ISD-ASes on the path.
        :returns: the request misc.
        :rtype: OPTMiscRequest
        """
        p = cls.P_CLS.new_message(sessionID=session_id)
        proto_path = p.init("path", len(path))
        for i, isd_as in enumerate(path):
            proto_path[i] = isd_as.int()
        return cls(p)

    def __str__(self):
        return "%s: SessionID: %s " % (self.NAME, self.p.sessionID)


class OPTMiscReply(DRKeyMiscBase):
    NAME = "OPTMiscReply"
    P_CLS = P.MiscOPTRep

    def __init__(self, p):
        super().__init__(p)
        self.raw_drkeys = []
        self.drkeys = []  # set by protocol.parse_misc_reply. [ProtocolDRKey] of on-path ASes.
        for drkey in p.drkeys:
            self.raw_drkeys.append(drkey)

    @classmethod
    def from_values(cls, drkeys=None):
        """
        Create OPTMiscRequest from values.

        :param [bytes] drkeys: list of raw on-path DRKeys.
        :returns: the reply misc.
        :rtype: OPTMiscReply
        """
        p = cls.P_CLS.new_message()
        proto_drkeys = p.init("drkeys", len(drkeys))
        for i, drkey in enumerate(drkeys):
            proto_drkeys[i] = drkey
        return cls(p)

    def __str__(self):
        return "%s" % (self.NAME)
