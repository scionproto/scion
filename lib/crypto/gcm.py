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
:mod:`gcm` --- AES-GCM encryption functions
===========================================
"""
from lib.crypto.aes import AES
import struct


def _xor_strings(xs, ys):
    """

    :param xs:
    :type xs:
    :param ys:
    :type ys:

    :returns:
    :rtype:
    """
    y = [xs[j] ^ ys[j] for j in range(len(xs))]
    return struct.pack('B' * len(y), *y)


def _gcm_rightshift(vec):
    """

    :param vec:
    :type vec:

    :returns:
    :rtype:
    """
    for x in range(15, 0, -1):
        c = vec[x] >> 1
        c |= (vec[x-1] << 7) & 0x80
        vec[x] = c
    vec[0] >>= 1
    return vec


def _gcm_gf_mult(a, b):
    """

    :param a:
    :type a:
    :param b:
    :type b:

    :returns:
    :rtype:
    """
    mask = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]
    poly = [0x00, 0xe1]
    Z = [0] * 16
    V = [c for c in a]
    for x in range(128):
        if b[x >> 3] & mask[x & 7]:
            Z = [V[y] ^ Z[y] for y in range(16)]
        bit = V[15] & 1
        V = _gcm_rightshift(V)
        V[0] ^= poly[bit]
    return Z


def _ghash(h, auth_data, data):
    """

    :param h:
    :type h:
    :param auth_data:
    :type auth_data:
    :param data:
    :type data:

    :returns:
    :rtype:
    """
    u = (16 - len(data)) % 16
    v = (16 - len(auth_data)) % 16
    x = auth_data
    x += bytes.fromhex('00'*v)
    if data is not None:
        x += data
    x += bytes.fromhex('00'*u)
    x += struct.pack('>QQ', len(auth_data) * 8, len(data) * 8)
    y = [0] * 16
    vec_h = h
    for i in range(0, len(x), 16):
        block = x[i:i+16]
        y = [y[j] ^ block[j] for j in range(16)]
        y = _gcm_gf_mult(y, vec_h)
    return struct.pack('B' * len(y), *y)


def _inc32(block):
    """

    :param block:
    :type block:

    :returns:
    :rtype:
    """
    counter, = struct.unpack('>L', block[12:])
    counter += 1
    return block[:12] + struct.pack('>L', counter)


def _gctr(cipher, expandedKey, nbrRounds, icb, plaintext):
    """

    :param cipher:
    :type cipher:
    :param expandedKey:
    :type expandedKey:
    :param nbrRounds:
    :type nbrRounds:
    :param icb:
    :type icb:
    :param plaintext:
    :type plaintext:

    :returns:
    :rtype:
    """
    y = bytes()
    if len(plaintext) == 0:
        return y
    cb = icb
    for i in range(0, len(plaintext), 16):
        cb = _inc32(cb)
        encrypted = cipher.encrypt(cb, expandedKey, nbrRounds)
        encrypted = struct.pack('B' * len(encrypted), *encrypted)
        plaintext_block = plaintext[i:i+16]
        y += _xor_strings(plaintext_block, encrypted[:len(plaintext_block)])
    return y


def gcm_decrypt(key_cache, iv, encrypted, auth_data, tag):
    """

    :param key_cache:
    :type key_cache:
    :param iv:
    :type iv:
    :param encrypted:
    :type encrypted:
    :param auth_data:
    :type auth_data:
    :param tag:
    :type tag:

    :returns:
    :rtype:
    """
    aes = AES()
    nbrRounds = 0
    esize = len(key_cache)
    if esize == aes.ekeySize['SIZE_128']:
        nbrRounds = 10
    elif esize == aes.ekeySize['SIZE_192']:
        nbrRounds = 12
    elif esize == aes.ekeySize['SIZE_256']:
        nbrRounds = 14
    else:
        raise ValueError('Expanded key size is incorrect.'
                         'Size should be 176, 208, or either 240 bytes.')
    h = aes.encrypt([0] * 16, key_cache, nbrRounds)
    if not iv:
        iv = bytes(16)
    if len(iv) == 12:
        y0 = iv + bytes.fromhex('00 00 00 01')
    else:
        y0 = _ghash(h, bytes(), iv)
    decrypted = _gctr(aes, key_cache, nbrRounds, y0, encrypted)
    s = _ghash(h, auth_data, encrypted)
    t = aes.encrypt(y0, key_cache, nbrRounds)
    t = struct.pack('B' * len(t), *t)
    T = _xor_strings(s, t)
    if T != tag:
        raise ValueError('Decrypted data is invalid')
    else:
        return decrypted


def gcm_encrypt(key_cache, iv, plaintext, auth_data):
    """

    :param key_cache:
    :type key_cache:
    :param iv:
    :type iv:
    :param plaintext:
    :type plaintext:
    :param auth_data:
    :type auth_data:

    :returns:
    :rtype:
    """
    aes = AES()
    nbrRounds = 0
    esize = len(key_cache)
    if esize == aes.ekeySize['SIZE_128']:
        nbrRounds = 10
    elif esize == aes.ekeySize['SIZE_192']:
        nbrRounds = 12
    elif esize == aes.ekeySize['SIZE_256']:
        nbrRounds = 14
    else:
        raise ValueError('Expanded key size is incorrect.'
                         'Size should be 176, 208, or either 240 bytes.')
    h = aes.encrypt([0] * 16, key_cache, nbrRounds)
    if not iv:
        iv = bytes(16)
    if len(iv) == 12:
        y0 = iv + bytes.fromhex('00 00 00 01')
    else:
        y0 = _ghash(h, bytes(), iv)
    encrypted = _gctr(aes, key_cache, nbrRounds, y0, plaintext)
    s = _ghash(h, auth_data, encrypted)
    t = aes.encrypt(y0, key_cache, nbrRounds)
    t = struct.pack('B' * len(t), *t)
    T = _xor_strings(s, t)
    return (encrypted, T)
