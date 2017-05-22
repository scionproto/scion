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
:mod:`symcrypto` --- SCION symmetric crypto functions
=====================================================
"""
# Stdlib
import hashlib

# External packages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.cmac import CMAC

# SCION
from lib.errors import SCIONTypeError
from lib.types import HashType


def mac(key, msg):
    """
    Default MAC function (CMAC using AES-128).

    Args:
        key: key for MAC creation.
        msg: Plaintext to be MACed, as a bytes object.

    Returns:
        MAC output, as a bytes object.

    Raises:
        ValueError: An error occurred when key is NULL or ciphertext is NULL.
    """
    if key is None:
        raise ValueError('Key is NULL.')
    elif msg is None:
        raise ValueError('Message is NULL.')
    else:
        cobj = CMAC(AES(key), backend=default_backend())
        cobj.update(msg)
        return cobj.finalize()


def kdf(secret, phrase):
    """
    Default key derivation function.
    """
    return hashlib.pbkdf2_hmac('sha256', secret, phrase, 1000)[:16]


def sha256(data):
    """
    Default hash function.
    """
    digest = hashlib.sha256()
    digest.update(data)
    return digest.digest()


# Default hash function
crypto_hash = sha256


def hash_func_for_type(type):
    """
    Returns a callable corresponding to 'type'.
    """
    if type == HashType.SHA256:
        return sha256
    raise SCIONTypeError("Unknown hash function type.")
