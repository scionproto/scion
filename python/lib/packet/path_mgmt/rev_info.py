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
# Stdlib
import logging
# External
import capnp  # noqa

# SCION
import proto.rev_info_capnp as P
from lib.packet.path_mgmt.base import PathMgmtPayloadBase
from lib.packet.scion_addr import ISD_AS
from lib.types import PathMgmtType as PMT


class RevocationInfo(PathMgmtPayloadBase):
    """
    Class containing revocation information, i.e., the revocation token.
    """
    NAME = "RevocationInfo"
    PAYLOAD_TYPE = PMT.REVOCATION
    P_CLS = P.RevInfo

    @classmethod
    def from_values(cls, isd_as, if_id, epoch, nonce, siblings, prev_root,
                    next_root, hash_type):
        """
        Returns a RevocationInfo object with the specified values.

        :param ISD_AS isd_as: The ISD_AS of the issuer of the revocation.
        :param int if_id: ID of the interface to be revoked
        :param int epoch: Time epoch for which interface is to be revoked
        :param bytes nonce: Nonce for the (if_id, epoch) leaf in the hashtree
        :param list[(bool, bytes)] siblings: Positions and hashes of siblings
        :param bytes prev_root: Hash of the tree root at time T-1
        :param bytes next_root: Hash of the tree root at time T+1
        :param hash_type: The hash function needed to verify the revocation.
        """
        # Put the isd_as, if_id, epoch and nonce of the leaf into the proof.
        p = cls.P_CLS.new_message(isdas=int(isd_as), ifID=if_id, epoch=epoch,
                                  nonce=nonce, hashType=hash_type)
        # Put the list of sibling hashes (along with l/r) into the proof.
        sibs = p.init('siblings', len(siblings))
        for i, sibling in enumerate(siblings):
            sibs[i].isLeft, sibs[i].hash = sibling
        # Put the roots of the hash trees at T-1 and T+1.
        p.prevRoot = prev_root
        p.nextRoot = next_root
        return cls(p)

    def isd_as(self):
        return ISD_AS(self.p.isdas)

    def cmp_str(self):
        b = []
        b.append(self.p.isdas.to_bytes(4, 'big'))
        b.append(self.p.ifID.to_bytes(8, 'big'))
        b.append(self.p.epoch.to_bytes(8, 'big'))
        b.append(self.p.nonce)
        return b"".join(b)

    def __eq__(self, other):
        if other is None:
            logging.error("Other RevInfo object is None.")
            return False
        return self.cmp_str() == other.cmp_str()

    def __hash__(self):
        return hash(self.cmp_str())

    def short_desc(self):
        return "RevInfo: %s IF: %d EPOCH: %d" % (self.isd_as(), self.p.ifID,
                                                 self.p.epoch)
