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
:mod:`protocol` --- SCION DRKey Protocol rules for authenticated SCMP
=====================================================
"""
# External
import copy

# SCION
from lib.crypto.symcrypto import mac
from lib.drkey.drkey_mgmt import DRKeyProtocolRequest
from lib.drkey.types import (
    DRKeyProtocolBase,
    DRKeyProtocols,
    DRKeyProtoKeyType,
    FirstOrderDRKey,
    SecondOrderDRKey,
)
from lib.drkey.util import drkey_time, get_drkey_exp_time
from lib.errors import SCIONVerificationError
from lib.msg_meta import UDPMetadata
from lib.packet.scion import SCIONCommonHdr
from lib.packet.spse.scmp_auth.ext_drkey import (
    SCMPAuthDRKeyDirections,
    SCMPAuthDRKeyLengths,
    SCMPAuthDRKeyExtn,
)
from lib.types import ExtensionClass

BLOCK_SIZE = 16


class SCMPAuthProtocol(DRKeyProtocolBase):

    PREFIX = b"SCMP"

    @staticmethod
    def verify_request(req, meta):
        assert isinstance(req, DRKeyProtocolRequest)
        assert isinstance(meta, UDPMetadata)

        if req.p.reqType == DRKeyProtoKeyType.AS_TO_AS:
            # TODO(roosd): only if a AS element
            raise SCIONVerificationError("Host is not an AS element")
        elif req.p.reqType == DRKeyProtoKeyType.AS_TO_HOST:
            # FIXME(roosd): add meta.ia. One sciond per AS currently.
            if (meta.ia, ) not in ((req.src_ia, ), (req.dst_ia, )):
                raise SCIONVerificationError("Requester %s:%s has no access" % (meta.ia, meta.host))
            if not req.dst_host:
                raise SCIONVerificationError("Destination host not set")
        elif req.p.reqType == DRKeyProtoKeyType.HOST_TO_HOST:
            if (meta.ia, ) not in ((req.src_ia, ), (req.dst_ia, )):
                raise SCIONVerificationError("Requester %s:%s has no access" % (meta.ia, meta.host))
            if not req.dst_host or not req.src_host:
                raise SCIONVerificationError("Host not set")
        else:
            raise SCIONVerificationError("Invalid request code %s" % req.p.reqType)

    @staticmethod
    def required_drkeys(req, meta):
        return [FirstOrderDRKey(req.src_ia, req.dst_ia, get_drkey_exp_time())]

    @classmethod
    def generate_drkey(cls, drkeys, req, meta):
        assert isinstance(drkeys[0], FirstOrderDRKey)
        assert isinstance(req, DRKeyProtocolRequest)
        assert isinstance(meta, UDPMetadata)
        assert len(drkeys) == 1
        assert req.src_ia == drkeys[0].src_ia
        assert req.dst_ia == drkeys[0].dst_ia

        if req.p.reqType == DRKeyProtoKeyType.AS_TO_AS:
            return cls._derive_drkey(drkeys[0])
        elif req.p.reqType == DRKeyProtoKeyType.AS_TO_HOST:
            return cls._derive_drkey(drkeys[0], req.dst_host)
        elif req.p.reqType == DRKeyProtoKeyType.HOST_TO_HOST:
            return cls._derive_drkey(drkeys[0], req.src_host, req.dst_host)
        else:
            return None


def verify_scmp_packet(spkt, drkey):
    assert isinstance(drkey, SecondOrderDRKey)
    extn = _find_scmp_auth_extn(spkt)
    if not extn:
        raise SCIONVerificationError("No SCMPAuth header")
    if not _is_correct_drkey(spkt, extn, drkey):
        raise SCIONVerificationError("Wrong DRKey: %s", drkey)
    computed = _compute_mac(spkt, drkey)
    if extn.mac != computed:
        raise SCIONVerificationError("Invalid MAC %s. Expected %s" %
                                     (extn.mac.hex(), computed.hex()))


def _is_correct_drkey(spkt, extn, drkey):
    assert isinstance(drkey, SecondOrderDRKey)
    if extn.direction == SCMPAuthDRKeyDirections.AS_TO_AS:
        return drkey.tuple() == (
            DRKeyProtoKeyType.AS_TO_AS, DRKeyProtocols.SCMP_AUTH, None,
            None, None, spkt.addrs.src.isd_as, spkt.addrs.dst.isd_as, None)
    if extn.direction == SCMPAuthDRKeyDirections.AS_TO_HOST:
        return drkey.tuple() == (
            DRKeyProtoKeyType.AS_TO_HOST, DRKeyProtocols.SCMP_AUTH, None,
            spkt.addrs.dst.host, None, spkt.addrs.src.isd_as, spkt.addrs.dst.isd_as, None)
    if extn.direction == SCMPAuthDRKeyDirections.HOST_TO_HOST:
        return drkey.tuple() == (
            DRKeyProtoKeyType.HOST_TO_HOST, DRKeyProtocols.SCMP_AUTH, spkt.addrs.src.host,
            spkt.addrs.dst.host, None, spkt.addrs.src.isd_as, spkt.addrs.dst.isd_as, None)
    if extn.direction == SCMPAuthDRKeyDirections.HOST_TO_AS:
        return drkey.tuple() == (
            DRKeyProtoKeyType.AS_TO_HOST, DRKeyProtocols.SCMP_AUTH, None,
            spkt.addrs.src.host, None, spkt.addrs.dst.isd_as, spkt.addrs.src.isd_as, None)
    if extn.direction == SCMPAuthDRKeyDirections.AS_TO_AS_REVERSED:
        return drkey.tuple() == (
            DRKeyProtoKeyType.AS_TO_AS, DRKeyProtocols.SCMP_AUTH, None,
            None, None, spkt.addrs.dst.isd_as, spkt.addrs.src.isd_as, None)
    if extn.direction == SCMPAuthDRKeyDirections.HOST_TO_HOST_REVERSED:
        return drkey.tuple() == (
            DRKeyProtoKeyType.HOST_TO_HOST, DRKeyProtocols.SCMP_AUTH, spkt.addrs.dst.host,
            spkt.addrs.src.host, None, spkt.addrs.dst.isd_as, spkt.addrs.src.isd_as, None)
    return False


def set_scmp_auth_mac(spkt, drkey):
    assert isinstance(drkey, SecondOrderDRKey)
    extn = _find_scmp_auth_extn(spkt)
    if not extn:
        return
    extn.mac = _compute_mac(spkt, drkey)


def _compute_mac(spkt, drkey):
    assert isinstance(drkey, SecondOrderDRKey)
    pkt = copy.deepcopy(spkt)
    extn = _find_scmp_auth_extn(pkt)
    if not extn:
        return None
    extn.mac = bytes(SCMPAuthDRKeyLengths.MAC)
    pkt.ext_hdrs = [e for e in pkt.ext_hdrs if e.EXT_CLASS == ExtensionClass.END_TO_END]
    packed = [pkt.pack()[SCIONCommonHdr.LEN:]]
    padding = ((BLOCK_SIZE - sum((len(p) for p in packed)) % BLOCK_SIZE) % BLOCK_SIZE)
    packed.append(bytes(padding))
    return mac(drkey.drkey, b"".join(packed))


def _find_scmp_auth_extn(spkt):
    for e in spkt.ext_hdrs:
        if isinstance(e, SCMPAuthDRKeyExtn):
            return e
    return None


def get_sciond_params(spkt):
    extn = _find_scmp_auth_extn(spkt)
    if not extn:
        return None

    params = DRKeyProtocolRequest.Params()
    params.protocol = DRKeyProtocols.SCMP_AUTH
    params.request_id = 0
    params.timestamp = drkey_time()

    if extn.direction == SCMPAuthDRKeyDirections.AS_TO_AS:
        # MAC created with key S->D
        params.request_type = DRKeyProtoKeyType.AS_TO_AS
        params.src_ia = spkt.addrs.src.isd_as
        params.dst_ia = spkt.addrs.dst.isd_as
    elif extn.direction == SCMPAuthDRKeyDirections.AS_TO_HOST:
        # MAC created with key S -> D:HD
        params.request_type = DRKeyProtoKeyType.AS_TO_HOST
        params.src_ia = spkt.addrs.src.isd_as
        params.dst_ia = spkt.addrs.dst.isd_as
        params.dst_host = spkt.addrs.dst.host
    elif extn.direction == SCMPAuthDRKeyDirections.HOST_TO_HOST:
        # MAC created with key S:HS -> D:HD
        params.request_type = DRKeyProtoKeyType.HOST_TO_HOST
        params.src_ia = spkt.addrs.src.isd_as
        params.src_host = spkt.addrs.src.host
        params.dst_ia = spkt.addrs.dst.isd_as
        params.dst_host = spkt.addrs.dst.host
    elif extn.direction == SCMPAuthDRKeyDirections.HOST_TO_AS:
        # MAC created with key D -> S:HS
        params.request_type = DRKeyProtoKeyType.AS_TO_HOST
        params.src_ia = spkt.addrs.dst.isd_as
        params.dst_ia = spkt.addrs.src.isd_as
        params.dst_host = spkt.addrs.src.host
    elif extn.direction == SCMPAuthDRKeyDirections.AS_TO_AS_REVERSED:
        # MAC created with key D -> S
        params.request_type = DRKeyProtoKeyType.AS_TO_AS
        params.src_ia = spkt.addrs.dst.isd_as
        params.dst_ia = spkt.addrs.src.isd_as
    elif extn.direction == SCMPAuthDRKeyDirections.HOST_TO_HOST_REVERSED:
        # MAC created with key D:HD -> S:HS
        params.request_type = DRKeyProtoKeyType.HOST_TO_HOST
        params.src_ia = spkt.addrs.dst.isd_as
        params.src_host = spkt.addrs.dst.host
        params.dst_ia = spkt.addrs.src.isd_as
        params.dst_host = spkt.addrs.src.host
    else:
        return None
    return params
