# Copyright 2014 ETH Zurich
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
:mod:`rev_obj` --- Revocation object
====================================
"""
# External
import capnp  # noqa

# SCION
from lib.packet.packet_base import Cerealizable
from lib.packet.path_mgmt.rev_info import RevocationInfo
import proto.rev_info_capnp as P


class RevocationObject(Cerealizable):
    """
    Revocation object that gets stored to Zookeeper.
    """
    NAME = "RevocationObject"
    P_CLS = P.RevObj

    @classmethod
    def from_values(cls, if_id, isd_as, rev_info):
        """
        Returns a RevocationInfo object with the specified values.

        :param int if_id: ID of the interface to be revoked
        :param int isd_as: ISD/AS of the interface to be revoked
        :param RevocationInfo rev_info
        """
        p = cls.P_CLS.new_message(ifID=if_id, isdAS=isd_as, revInfo=rev_info)
        return cls(p)

    def rev_info(self):
        return RevocationInfo(self.p.revInfo)

    def __len__(self):
        raise NotImplementedError

    def __str__(self):
        return "%s: IF id: %s ISD_AS: %s Rev info: %s" % (
            self.NAME, self.p.ifID, self.p.isdAS, self.p.revInfo)
