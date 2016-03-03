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
# External packages
from Crypto.Cipher import AES


def cbcmac(key, msg):
    """
    CBC-MAC using AES-128.

    Args:
        key: key for MAC creation.
        msg: Plaintext to be MACed, as a bytes object.

    Returns:
        MAC output, as a bytes object.

    Raises:
        ValueError: An error occurred when key is NULL or ciphertext is NULL.

    Warnings:
        CBC-MAC is insecure for variable size messages.
    """
    if key is None:
        raise ValueError('Key is NULL.')
    elif msg is None:
        raise ValueError('Message is NULL.')
    else:
        iv = b"\x00" * 16
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(msg)[-16:]  # Return the last block of ciphertext.
