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
from lib.crypto.python_sha3 import Keccak
from lib.crypto.aes import AES
from lib.crypto.gcm import gcm_encrypt
from lib.crypto.gcm import gcm_decrypt
from lib.packet.opaque_field import HopOpaqueField
import os
import struct
import math


def _append_pkcs7_padding(msg):
    """
    PKCS7 Padding functions to a given message msg.

    :param msg:
    :type msg:
    """
    numpads = 16 - (len(msg) % 16)
    return msg + bytes([numpads]*numpads)


def _strip_pkcs7_padding(msg):
    """
    Strip PKCS7 Padding from to a given message msg with PKCS7 padding.

    :param msg:
    :type msg:
    """
    if len(msg) % 16 or not msg:
        raise ValueError('Bytes of len %d can\'t be PCKS7-padded' % len(msg))
    numpads = msg[-1]
    if numpads > 16:
        raise ValueError('Bytes ending with %r can\'t be PCKS7-padded' %
                         msg[-1])
    return msg[:-numpads]


def get_random_bytes(size):
    """
    Generates random bytes of length `size`. The randomness source comes from
    default random resource from operating systems. e.g., /dev/urandom on Linux
    OS.

    :param size: Length of generated random bytes, should be greater than 0.
    :type size:

    :returns: Random output, as a bytes object.
    :rtype:

    ...Raises:
       ValueError: An error occurred when size is not a positive integer.
    """
    if size > 0:
        return os.urandom(size)
    else:
        raise ValueError('Invalid len, %s. Should be greater than 0.' % size)


def sha3hash(inp=None, algo='SHA3-512'):
    """
    Sha3 hash function with given data and supported algorithm options.

    :param inp: Hash input, as a string. Default value is NULL.
    :type inp:
    :param algo: Supported SHA3 algorithms, as a string. Algorithms include
                 `SHA3-224`, `SHA3-256`, `SHA3-384`, and `SHA3-512`.
                 Default option is `SHA3-512`.
    :type algo:

    :returns: Hash output, as a bytes object.
    :rtype:

    ...Raises:
       ValueError: An error occurred when algorithm is not recognized.
    """
    if algo == 'SHA3-224':
        return Keccak(c=448, r=1152, n=224, data=inp).hexdigest()
    elif algo == 'SHA3-256':
        return Keccak(c=512, r=1088, n=256, data=inp).hexdigest()
    elif algo == 'SHA3-384':
        return Keccak(c=768, r=832, n=384, data=inp).hexdigest()
    elif algo == 'SHA3-512':
        return Keccak(c=1024, r=576, n=512, data=inp).hexdigest()
    else:
        raise ValueError("Hash algorithm does not implement.")


def get_roundkey_cache(key):
    """
    Key expansion function for AES encryption based symmetric crypto schemes.
    The output (expanded key cache) can be used on either CBC block cipher (see
    cbc_encrypt and cbc_decrypt), authenticated encryption (see
    authenticated_encrypt and authenticated_decrypt), or CBC-MAC (see get_cbcmac
    and verify_cbcmac).

    :param key: Symmetric key for AES cipher, as a bytes object.
    :type key:

    :returns: Expanded round key cache, as a list.
    :rtype:

    ...Raises:
       ValueError: An error occurred when key is NULL or length of key is
       incorrect.
    """
    if key is None:
        raise ValueError('Key is NULL.')
    else:
        aes = AES()
        nbr_rounds = 0
        size = len(key)
        if size == aes.keySize['SIZE_128']:
            nbr_rounds = 10
        elif size == aes.keySize['SIZE_192']:
            nbr_rounds = 12
        elif size == aes.keySize['SIZE_256']:
            nbr_rounds = 14
        else:
            raise ValueError('Key size is incorrect.'
                             'Size should be 16, 24, or either 32 bytes.')
        expanded_keysize = 16 * (nbr_rounds + 1)
        return aes.expandKey(key, size, expanded_keysize)


def cbc_encrypt(cache, msg, inv=None):
    """
    CBC cipher encryption on a given message with pre-expanded key cache.

    :param cache: Expanded round key cache by calling get_roundkey_cache.
    :type cache:
    :param msg: Plaintext to be encrypted, as a bytes object.
    :type msg:
    :param inv: Initialized vector for CBC cipher, as a bytes object. Default
                value is NULL.
    :type inv:

    :returns: Encrypted block cipher, as a bytes object.
    :rtype:

    ...Raises:
       ValueError: An error occurred when cache is NULL or msg is NULL.
    """
    if cache is None:
        raise ValueError('Key cache is NULL.')
    elif msg is None:
        raise ValueError('Message is NULL.')
    else:
        aes = AES()
        nbr_rounds = 0
        esize = len(cache)
        if esize == aes.ekeySize['SIZE_128']:
            nbr_rounds = 10
        elif esize == aes.ekeySize['SIZE_192']:
            nbr_rounds = 12
        elif esize == aes.ekeySize['SIZE_256']:
            nbr_rounds = 14
        else:
            raise ValueError('Expanded key has incorrect size.'
                             'Size should be 176, 208, or either 240 bytes.')
        plaintext = []
        iput = [0] * 16
        output = []
        cipher = [0] * 16
        string_in = _append_pkcs7_padding(msg)
        if inv is None:
            inv = [0] * 16
        first_round = True
        if string_in is not None:
            for j in range(int(math.ceil(float(len(string_in))/16))):
                start = j * 16
                end = start + 16
                if end > len(string_in):
                    end = len(string_in)
                plaintext = string_in[start:end]
                for i in range(16):
                    if first_round:
                        iput[i] = plaintext[i] ^ inv[i]
                    else:
                        iput[i] = plaintext[i] ^ cipher[i]
                first_round = False
                cipher = aes.encrypt(iput, cache, nbr_rounds)
                output.extend(cipher)
        return struct.pack('B' * len(output), *output)


def cbc_decrypt(cache, cipher, inv=None):
    """
    CBC cipher decryption on a given cipher with pre-expanded key cache.

    Args:
        cache: Expanded round key cache by calling get_roundkey_cache.
        cipher: Ciphertext to be decrypted, as a bytes object.
        inv: Initialized vector for CBC cipher, as a bytes object. Default
        value is NULL.

    Returns:
        Decrypted output, as a bytes object.

    Raises:
        ValueError: An error occurred when cache is NULL or ciphertext is NULL.
    """
    if cache is None:
        raise ValueError('Key cache is NULL.')
    elif cipher is None:
        raise ValueError('Ciphertext is NULL.')
    else:
        aes = AES()
        nbr_rounds = 0
        esize = len(cache)
        if esize == aes.ekeySize['SIZE_128']:
            nbr_rounds = 10
        elif esize == aes.ekeySize['SIZE_192']:
            nbr_rounds = 12
        elif esize == aes.ekeySize['SIZE_256']:
            nbr_rounds = 14
        else:
            raise ValueError('Expanded key has size incorrect.'
                             'Size should be 176, 208, or either 240 bytes.')
        # the AES input/output
        ciphertext = []
        iput = []
        output = []
        plaintext = [0] * 16
        # the output plain text string
        string_out = bytes()
        if inv is None:
            inv = [0] * 16
        # char firstRound
        first_round = True
        if cipher is not None:
            for j in range(int(math.ceil(float(len(cipher))/16))):
                start = j * 16
                end = start + 16
                if j * 16 + 16 > len(cipher):
                    end = len(cipher)
                ciphertext = cipher[start:end]
                output = aes.decrypt(ciphertext, cache, nbr_rounds)
                for i in range(16):
                    if first_round:
                        plaintext[i] = inv[i] ^ output[i]
                    else:
                        plaintext[i] = iput[i] ^ output[i]
                first_round = False
                string_out += struct.pack('B' * len(plaintext), *plaintext)
                iput = ciphertext
        string_out = _strip_pkcs7_padding(string_out)
        return string_out


def get_cbcmac(cache, msg):
    """
    Message Authentication Code with pre-expanded key cache and a given input
    message.

    Args:
        cache: Expanded round key cache by calling get_roundkey_cache.
        msg: Plaintext to be MACed, as a bytes object.

    Returns:
        MAC output, as a bytes object.

    Raises:
        ValueError: An error occurred when cache is NULL or ciphertext is NULL.
    """
    if cache is None:
        raise ValueError('Key cache is NULL.')
    elif msg is None:
        raise ValueError('Message is NULL.')
    else:
        inv = [0] * 16
        inv[0] = len(msg)
        cipher = cbc_encrypt(cache, msg, inv)
        return cipher[-16:]


def verify_cbcmac(cache, msg, rmac):
    """
    Message Authentication Code Verification with pre-expanded key cache, a
    given input message, and the corresponding MAC of message itself.

    Args:
        cache: Expanded round key cache by calling get_roundkey_cache.
        msg: Plaintext to be MACed, as a bytes object.
        rmac: Received MAC of msg, as a bytes object.

    Returns:
        Verification result, as a boolean value.

    Raises:
        ValueError: An error occurred when cache is NULL or msg is NULL.
    """
    if cache is None:
        raise ValueError('Key cache is NULL.')
    elif msg is None:
        raise ValueError('Message is NULL.')
    else:
        mac = get_cbcmac(cache, msg)
        return mac == rmac


def authenticated_encrypt(cache, msg, auth, inv=None):
    """
    Message Encryption using AES-GCM with pre-expanded key cache, a given
    plaintext, an authentication data, and initialized vector.

    Args:
        cache: Expanded round key cache by calling get_roundkey_cache.
        msg: Plaintext to be encrypted, as a bytes object.
        auth: Authentication data, as a bytes object.
        inv: Initialized vector, as a bytes object. Default value is NULL.

    Returns:
        Concatenated cipher (c, t) where c is protected cipher and t is
        authenticated tag.
    """
    cipher, tag = gcm_encrypt(cache, inv, msg, auth)
    return cipher+tag


def authenticated_decrypt(cache, cipher, auth, inv=None):
    """
    Message Decryption using AES-GCM with pre-expanded key cache, a given
    cipher, an authentication data, and initialized vector.

    Args:
        cache: Expanded round key cache by calling get_roundkey_cache.
        cipher: Ciphertext to be decrypted, as a bytes object.
        auth: Authentication data, as a bytes object.
        inv: Initialized vector, as a bytes object. Default value is NULL.

    Returns:
        Decrypted result, as a bytes object. If authentication fails, raise an
        exception to abort.
    """
    ciphertext = cipher[:-16]
    tag = cipher[-16:]
    decipher = gcm_decrypt(cache, inv, ciphertext, auth, tag)
    return decipher


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
    ts_raw = struct.pack("I", ts)
    to_mac = hof_raw + prev_hof_raw + ts_raw
    return get_cbcmac(key, to_mac)[:HopOpaqueField.MAC_LEN]


def verify_of_mac(key, hof, prev_hof, ts):
    """
    Verifies MAC of OF.
    """
    return hof.mac == gen_of_mac(key, hof, prev_hof, ts)
