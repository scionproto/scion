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
:mod:`drkey_mgmt` --- SCION DRKey management packets
=====================================================
"""
# External
import capnp  # noqa

# SCION
import proto.drkey_mgmt_capnp as P

from lib.packet.packet_base import CerealBox, Cerealizable
from lib.packet.scion_addr import ISD_AS
from lib.types import DRKeyMgmtType


class DRKeyMgmt(CerealBox):  # pragma: no cover
    NAME = "DRKeyMgmt"
    P_CLS = P.DRKeyMgmt
    # Set at end of file, after classes have been defined.
    CLASS_FIELD_MAP = None


class DRKeyRequest(Cerealizable):
    """ First order DRKey request. """
    NAME = "DRKeyRequest"
    P_CLS = P.DRKeyReq

    def __init__(self, p):
        super().__init__(p)
        self.isd_as = ISD_AS(p.isdas)

    @classmethod
    def from_values(cls, prefetch, isd_as, timestamp, signature, cert_ver, trc_ver):
        """
        Get DRKey request from values.

        :param Bool prefetch: indicates if request is for current (False) or next (True) DRKey.
        :param ISD_AS isd_as: source ISD-AS of the requested DRKey.
        :param int timestamp: signature creation time (format: drkey_time()).
        :param bytes signature: signature of (isd_as, prefetch, timestamp).
        :param int cert_ver: version of the certificate used to create signature.
        :param int trc_ver: version of the trc associated with the certificate.
        :returns: the resulting DRKeyRequest object.
        :rtype: DRKeyRequest
        """
        p = cls.P_CLS.new_message(isdas=isd_as.int(), timestamp=timestamp, signature=signature,
                                  certVer=cert_ver, trcVer=trc_ver)
        p.flags.prefetch = prefetch
        return cls(p)

    def short_desc(self):
        return ("ISD-AS: %s prefetch: %s TS: %s" %
                (self.isd_as, self.p.flags.prefetch, self.p.timestamp))


class DRKeyReply(Cerealizable):
    NAME = "DRKeyReply"
    P_CLS = P.DRKeyRep

    def __init__(self, p):
        super().__init__(p)
        self.isd_as = ISD_AS(p.isdas)

    @classmethod
    def from_values(cls, isd_as, time, exp_time, cipher, signature,
                    cert_ver_src, cert_ver_dst, trc_ver):
        """
        Get the DRKeyReply from values.

        :param ISD_AS isd_as: source ISD-AS of the DRKey.
        :param int time: signature creation time (format drkey_time()).
        :param int exp_time: expiration time of the first order DRKey.
        :param bytes cipher: the encrypted first order DRKey.
        :param bytes signature: the signature of (isd_as, cipher, time, exp_time).
        :param int cert_ver_src: version of certificate for signing key/public key.
        :param int cert_ver_dst: version of certificate for private key.
        :param int trc_ver: version of trc associated with source cert.
        :returns: the resulting DRKeyReply.
        :rtype: DRKeyReply
        """
        return cls(cls.P_CLS.new_message(
            isdas=isd_as.int(), timestamp=time, expTime=exp_time,
            cipher=cipher, signature=signature, certVerSrc=cert_ver_src,
            certVerDst=cert_ver_dst, trcVer=trc_ver))

    def short_desc(self):
        return ("ISD-AS: %s expTime: %s certs: (src=%s, dst=%s, trc=%s) TS: %s"
                % (self.isd_as, self.p.expTime, self.p.certVerSrc,
                   self.p.certVerDst, self.p.trcVer, self.p.timestamp))

DRKeyMgmt.CLASS_FIELD_MAP = {
    DRKeyRequest: DRKeyMgmtType.FIRST_ORDER_REQUEST,
    DRKeyReply: DRKeyMgmtType.FIRST_ORDER_REPLY,
}
