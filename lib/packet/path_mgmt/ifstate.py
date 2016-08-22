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
:mod:`ifstate` --- Interface State
=======================================
"""
# External
import capnp  # noqa

# SCION
import proto.if_state_capnp as P
from lib.packet.packet_base import Cerealizable
from lib.packet.path_mgmt.base import PathMgmtPayloadBase
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.types import PathMgmtType as PMT


class IFStateInfo(Cerealizable):  # pragma: no cover
    """
    StateInfo is used by the beacon server to inform border routers about any
    state changes of other border routers. It contains the ID of the router, the
    state (up or down), and the current revocation token and proof.
    """
    NAME = "IFStateInfo"
    P_CLS = P.IFStateInfo

    def __init__(self, p):
        super().__init__(p)
        self.rev_info = RevocationInfo(p.revInfo)

    @classmethod
    def from_values(cls, if_id, active, rev_info):
        return cls(cls.P_CLS.new_message(ifID=if_id, active=active,
                                         revInfo=rev_info.p))


class IFStatePayload(PathMgmtPayloadBase):  # pragma: no cover
    """
    Payload for state info messages. List of IFStateInfo objects.
    """
    NAME = "IFStatePayload"
    PAYLOAD_TYPE = PMT.IFSTATE_INFOS
    P_CLS = P.IFStateInfos

    @classmethod
    def from_values(cls, infos):
        """
        :param ifstate_infos: list of IFStateInfo objects
        """
        p = cls.P_CLS.new_message()
        p.init("infos", len(infos))
        for i, info in enumerate(infos):
            p.infos[i] = info.p
        return cls(p)


class IFStateRequest(PathMgmtPayloadBase):  # pragma: no cover
    """
    IFStateRequest encapsulates a request for interface states from an ER to
    the BS.
    """
    NAME = "IFStateRequest"
    PAYLOAD_TYPE = PMT.IFSTATE_REQ
    P_CLS = P.IFStateReq
    ALL_INTERFACES = 0

    @classmethod
    def from_values(cls, if_id=ALL_INTERFACES):
        return cls(cls.P_CLS.new_message(ifID=if_id))
