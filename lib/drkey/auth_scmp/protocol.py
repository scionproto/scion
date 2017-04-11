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
from Crypto.Cipher import AES

# SCION
from lib.crypto.symcrypto import cbcmac
from lib.drkey.drkey_mgmt import DRKeyProtocolRequest
from lib.drkey.types import DRKeyProtoReqType
from lib.msg_meta import UDPMetadata
from lib.packet.ext.security import SecurityExt, SecModes as SecM


def check_privilege(req, meta):
    assert isinstance(req, DRKeyProtocolRequest.Request)
    assert isinstance(meta, UDPMetadata)
    # TODO(roosd): check privilege
    return True


def generate_drkey(drkey, req, meta):
    assert isinstance(req, DRKeyProtocolRequest.Request)
    assert isinstance(meta, UDPMetadata)

    l = [req.dst_ia.pack()]
    if req.p.reqCode == DRKeyProtoReqType.AS_TO_HOST:
        l.append(req.dst_host.pack())
        l.append(bytes(16-req.dst_host.LEN))
    if req.p.reqCode == DRKeyProtoReqType.HOST_TO_HOST:
        l.append(req.dst_host.pack())
        l.append(bytes(16-req.dst_host.LEN))
        l.append(req.src_ia.pack())
        l.append(req.src_host.pack())
        l.append(bytes(16-req.src_host.LEN))
    l.append(b"SCMP")
    length = sum(map(lambda x: len(x), l))
    padding = ((AES.block_size - length % AES.block_size) % AES.block_size)
    l.append(bytes(padding))
    return cbcmac(drkey, b"".join(l))


def verify(spkt, drkey):
    scmp_auth_extn = find_scmp_auth_extn(spkt)
    if not scmp_auth_extn:
        return False
    return scmp_auth_extn.authenticator == compute_mac(spkt, drkey)


def find_scmp_auth_extn(spkt):
    for e in spkt.ext_hdrs:
        if isinstance(e, SecurityExt) and e.sec_mode == SecM.SCMP_AUTH_DRKEY:
            return e
    return None


def compute_mac(spkt, drkey):
    pkt = copy.deepcopy(spkt)
    scmp_auth_extn = find_scmp_auth_extn(pkt)
    if not scmp_auth_extn:
        return None
    scmp_auth_extn.authenticator = bytes(16)
    a = bytearray(pkt.pack())
    a[4:7] = bytes(3)
    padding = ((AES.block_size - len(a) % AES.block_size) % AES.block_size)
    a.extend(bytes(padding))
    return cbcmac(drkey, bytes(a))
