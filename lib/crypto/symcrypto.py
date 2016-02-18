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
import struct

# External packages
from Crypto.Cipher import AES

# SCION
from lib.packet.opaque_field import HopOpaqueField


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


def gen_of_mac(key, hof, prev_hof, ts):
    """
    Generates MAC for newly created OF.
    Takes newly created OF (except MAC field), previous HOF, and timestamp.
    """
    # TODO: this is stronly SCION-related, maybe move to other file?
    # Drop info field (as it changes) and MAC field (empty).
    hof_raw = hof.pack()[1:-HopOpaqueField.MAC_LEN]
    if prev_hof:
        prev_hof_raw = prev_hof.pack()[1:]  # Drop info field.
    else:
        # Constant length for CBC-MAC's security.
        prev_hof_raw = b"\x00" * (HopOpaqueField.LEN - 1)
    ts_raw = struct.pack("!I", ts)
    to_mac = hof_raw + prev_hof_raw + ts_raw + b"\x00"  # With \x00 as padding.
    return cbcmac(key, to_mac)[:HopOpaqueField.MAC_LEN]


def verify_of_mac(key, hof, prev_hof, ts):
    """
    Verifies MAC of OF.
    """
    return hof.mac == gen_of_mac(key, hof, prev_hof, ts)
