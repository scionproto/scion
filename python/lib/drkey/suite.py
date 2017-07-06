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
:mod:`suite` --- DRKey suite
============================

Rules for DRKey suite and first order DRKey exchange
"""

# External
import struct

# SCION
from lib.crypto.asymcrypto import encrypt, decrypt, sign
from lib.crypto.symcrypto import mac
from lib.drkey.drkey_mgmt import DRKeyReply, DRKeyRequest
from lib.drkey.util import drkey_time

##################
# DRKey Request  #
##################


def drkey_signing_input_req(isd_as, prefetch, timestamp):
    """
    Pack the input such that it can be signed.

    :param ISD_AS isd_as: the ISD-AS.
    :param Bool prefetch: indicator if prefetch (True) or not (False).
    :param int timestamp: signature creation time (format: drkey_time()).
    :returns: the packed signature input.
    :rtype: bytes
    """
    fetch = struct.pack("!B", prefetch)
    ts = struct.pack("!Q", timestamp)
    return b"".join([isd_as.pack(), fetch, ts])


def get_drkey_request(dst_ia, prefetch, signing_key, cert_ver, trc_ver):
    """
    Generate a DRKeyRequest. The Request is signed with the signing key of the
    specified certificate.

    :param ISD_AS dst_ia: destination of the DRKey request.
    :param Bool prefetch: indicator if prefetch (True) or not (False).
    :param bytes signing_key: the signing key
    :param int cert_ver: version of the certificate associated with singing key
    :param int trc_ver: version of the trc associated with the certificate.
    :returns: the signed DRKeyRequest.
    :rtype: DRKeyRequest
    """
    timestamp = drkey_time()
    signature = sign(drkey_signing_input_req(dst_ia, prefetch, timestamp), signing_key)
    return DRKeyRequest.from_values(prefetch, dst_ia, timestamp, signature, cert_ver, trc_ver)

##################
# DRKey Reply    #
##################


def derive_drkey_raw(sec_val, dst_ia):
    """
    Derive the raw first order DRKey (local AS -> dst_ia).

    :param DRKeySecretValue sec_val: secret value of local AS
    :param ISD_AS dst_ia: destination of first order DRKey.
    :returns: the raw first order DRKey.
    :rtype: bytes
    """
    return mac(sec_val.secret, b"".join(
        [struct.pack("!I", dst_ia._isd), struct.pack("!I", dst_ia._as), bytes(8)]))


def get_signing_input_rep(isd_as, timestamp, exp_time, cipher):
    """
    Pack the input such that it can be signed.

    :param ISD_AS isd_as: the ISD_AS.
    :param int timestamp: signature creation time (format: drkey_time()).
    :param int exp_time: DRKey expiration time (format: drkey_time()).
    :param bytes cipher: the encrypted first order DRKey.
    :returns: the packed input to sign.
    :rtype: bytes
    """
    ts = struct.pack("!Q", timestamp)
    exp = struct.pack("!Q", exp_time)
    return b"".join([isd_as.pack(), cipher, ts, exp])


def _encrypt_drkey(drkey, private_key, public_key):
    """
    Encrypt the first order DRKey.

    :param bytes drkey: the raw first order DRKey.
    :param bytes private_key: the local private key.
    :param bytes public_key: the raw public key.
    :return:
    """
    return bytes(encrypt(drkey, private_key, public_key))


def get_drkey_reply(sv, src_ia, dst_ia, priv_key, signing_key, cert_ver, dst_cert, trc_ver):
    """
    Generate a DRKeyReply. The Reply is signed with the signing key.
    The contained drkey is encrypted using the public key of the
    destination certificate.

    :param DRKeySecretValue sv: the local secret value used to derive the DRKey.
    :param ISD_AS src_ia: the local ISD-AS address.
    :param ISD_AS dst_ia: the ISD-AS for which the DRKey is computed.
    :param bytes priv_key: local private key.
    :param bytes signing_key: local signing key.
    :param int cert_ver: version of the certificate, priv_key and signing_key are associated with.
    :param Certificate dst_cert: the certificated of the destination ISD-AS.
    :param int trc_ver: version of trc associated with cert_ver.
    :returns: the resulting DRKeyReply
    :rtype: DRKeyReply
    """
    drkey = derive_drkey_raw(sv, dst_ia)
    cipher = bytes(encrypt(drkey, priv_key, dst_cert.subject_enc_key_raw))
    timestamp = drkey_time()
    signature = sign(get_signing_input_rep(src_ia, timestamp, sv.exp_time, cipher), signing_key)
    return DRKeyReply.from_values(src_ia, timestamp, sv.exp_time, cipher, signature,
                                  cert_ver, dst_cert.version, trc_ver)


def decrypt_drkey(cipher, private_key, public_key):
    """
    Decrypt the encrypted first order DRKey.

    :param bytes cipher: the encrypted DRKey
    :param bytes private_key: the local private key.
    :param bytes public_key: the public key of the sender.
    :returns: the raw first order DRKey.
    :rtype: bytes
    :raises: CryptoError
    """
    return decrypt(cipher, private_key, public_key)
