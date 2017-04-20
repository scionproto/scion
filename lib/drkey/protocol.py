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
:mod:`protocol` --- DRKey protocol
============================

Protocol rules in DRKey
"""

# External
import logging
import struct
import time
from nacl.public import PublicKey

# SCION
from lib.crypto.asymcrypto import encrypt, decrypt, sign
from lib.crypto.symcrypto import cbcmac
from lib.drkey.auth_scmp import protocol as auth_scmp
from lib.drkey.drkey_mgmt import DRKeyReply, DRKeyRequest
from lib.drkey.types import DRKeyProtocols

_privilege_checker_map = {
    # DRKeyProtocols.OPT: None,
    DRKeyProtocols.SCMP_AUTH: auth_scmp.check_privilege
}

_protocol_drkey_generator_map = {
    DRKeyProtocols.SCMP_AUTH: auth_scmp.generate_drkey
}


class DRKeyProtocol(object):

    class Params(object):
        secret = None       # Secret Value for DRKey derivation
        src_ia = None       # ISD-AS of AS
        dst_ia = None       # ISD-AS of recipient
        private_key = None  # Private key of AS. type: bytes
        public_key = None   # Public key of recipient. type: bytes
        prefetch = None     # is a prefetched key. type: bool
        signing_key = None  # Signing key of AS. type: bytes
        chain = None        # CertificateChain of AS.

    @staticmethod
    def get_exp_time(src_ia, dst_ia, timestamp, prefetch):
        # TODO(roosd): implement (timestamp is the creation time of message)
        return 0

    ###############################
    # DRKey Request
    ###############################

    @staticmethod
    def get_drkey_request(params):
        timestamp = int(time.time() * 1000000)
        fetch = struct.pack("!B", params.prefetch)
        ts = struct.pack("!Q", timestamp)
        signature = sign(b"".join([params.dst_ia.pack(), fetch, ts]),
                         params.signing_key)
        return DRKeyRequest.from_values(
            params.prefetch, params.dst_ia, timestamp, signature, params.chain)

    ###############################
    # DRKey Reply
    ###############################

    @staticmethod
    def derive_drkey(secret, dst_ia):
        return cbcmac(secret, b"".join([struct.pack("!I", dst_ia._isd),
                                        struct.pack("!I", dst_ia._as),
                                        bytes(8)]))

    @staticmethod
    def _get_cipher(drkey, private_key, public_key):
        return encrypt(drkey, private_key, PublicKey(public_key))

    @staticmethod
    def _get_signature(src_ia, cipher, prefetch, timestamp, signing_key):
        assert isinstance(prefetch, bool)
        fetch = struct.pack("!B", prefetch)
        ts = struct.pack("!Q", timestamp)
        return sign(b"".join([src_ia.pack(), cipher, fetch, ts]), signing_key)

    @staticmethod
    def get_drkey_reply(params):
        drkey = DRKeyProtocol.derive_drkey(params.secret, params.dst_ia)
        cipher = DRKeyProtocol._get_cipher(drkey, params.private_key,
                                           params.public_key)
        timestamp = int(time.time() * 1000000)
        signature = DRKeyProtocol._get_signature(
            params.src_ia, cipher, params.prefetch,
            timestamp, params.signing_key)
        return DRKeyReply.from_values(
            params.prefetch, params.src_ia, timestamp, cipher, signature,
            params.chain)

    @staticmethod
    def decrypt_drkey(cipher, private_key, public_key):
        return decrypt(cipher, private_key, PublicKey(public_key))

    ###############################
    # DRKey Protocol
    ###############################

    @staticmethod
    def get_privilege_checker(protocol):
        try:
            checker = _privilege_checker_map[protocol]
        except KeyError:
            logging.error("Protocol %s not supported.", protocol)
            return None
        return checker

    @staticmethod
    def get_protocol_drkey_generator(protocol):
        try:
            generator = _protocol_drkey_generator_map[protocol]
        except KeyError:
            logging.error("Protocol %s not supported.", protocol)
            return None
        return generator
