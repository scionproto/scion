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
:mod:`rev_info` --- Revocation info payload
============================================
"""
# External
import capnp  # noqa

# SCION
import proto.rev_info_capnp as P
from lib.packet.path_mgmt.base import PathMgmtPayloadBase
from lib.types import PathMgmtType as PMT


class RevocationInfo(PathMgmtPayloadBase):
    """
    Class containing revocation information, i.e., the revocation token.
    """
    NAME = "RevocationInfo"
    PAYLOAD_TYPE = PMT.REVOCATION
    P_CLS = P.RevInfo

    @classmethod
    def from_values(cls, rev_token):
        """
        Returns a RevocationInfo object with the specified values.

        :param bytes rev_token: revocation token of interface
        """
        return cls(cls.P_CLS.new_message(revToken=rev_token))
