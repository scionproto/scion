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
:mod:`asymcrypto` --- SCION asymmetric crypto functions
=======================================================
"""

from lib.crypto.nacl import crypto_sign_ed25519_keypair
from lib.crypto.nacl import crypto_box_curve25519xsalsa20poly1305_keypair
from lib.crypto.nacl import crypto_sign_ed25519
from lib.crypto.nacl import crypto_sign_ed25519_open
from lib.crypto.nacl import crypto_box_curve25519xsalsa20poly1305
from lib.crypto.nacl import crypto_box_curve25519xsalsa20poly1305_open
from lib.crypto.nacl import randombytes


def generate_signature_keypair():
    """
    Generate a key pair for ed25519 signature scheme.

    :returns: a pair containing the signing key and the verifying key.
    :rtype: bytes
    """
    (verifying_key, signing_key) = crypto_sign_ed25519_keypair()
    return (verifying_key, signing_key)


def generate_cryptobox_keypair():
    """
    Generate a key pair for CryptoBox scheme. The CryptoBox scheme constructs
    public-key based encryption involving ECDH over Curve 25519, stream cipher
    xsalsa20, and message authentication code poly1305.

    :returns: a key pair containing private key for decryption and public key
              for encryption.
    :rtype: bytes
    """
    (public_key, private_key) = crypto_box_curve25519xsalsa20poly1305_keypair()
    return (public_key, private_key)


def sign(msg, signing_key):
    """
    Sign a message with a given signing key and return the signature.

    :param msg: message to be signed.
    :type msg: bytes
    :param signing_key: signing key from generate_signature_keypair().
    :type signing_key: bytes

    :returns: ed25519 signature.
    :rtype: bytes
    """
    return crypto_sign_ed25519(msg, signing_key)[:64]


def verify(msg, sig, verifying_key):
    """
    Verify a signature.

    :param msg: message that was signed.
    :type msg: bytes
    :param sig: signature to verify.
    :type sig: bytes
    :param verifying_key: verifying key from generate_signature_keypair().
    :type verifying_key: bytes

    :returns: True or False whether the verification succeeds or fails.
    :rtype: boolean
    """
    try:
        crypto_sign_ed25519_open(sig + msg, verifying_key)
        return True
    except:
        return False


def encrypt(msg, private_key, recipient, chain):
    """
    Encrypt a message with CryptoBox scheme under a given private key and
    recipient's public key stored in certificate chain structure.

    :param msg: Plaintext to be encrypted.
    :type msg: string
    :param private_key: Sender's private key from generate_cryptobox_keypair().
    :type private_key: bytes
    :param recipient: Recipient's subject.
    :type recipient: string
    :param chain: Certificate chain containing the recipient's certificate.
    :type chain: :class:`CertificateChain`

    :returns: Protected ciphertext.
    :rtype: bytes

    .. Raises:
       ValueError: An error occurred when private key is NULL or msg is NULL.
       LookupError: An error occurred when recipient's public key has not been
       found in certificate chain.
    """
    if private_key is None:
        raise ValueError('Private key is NULL.')
    if msg is None:
        raise ValueError('Plaintext is NULL.')
    pub_key = None
    for recipient_cert in chain.certs:
        if recipient_cert.subject == recipient:
            pub_key = recipient_cert.subject_enc_key
            break
    if pub_key is None:
        raise LookupError('Recipient\'s public key has not been found.')
    nonce = randombytes(24)
    cipher = nonce + crypto_box_curve25519xsalsa20poly1305(msg, nonce, pub_key,
                                                           private_key)
    return cipher


def decrypt(cipher, private_key, sender, chain):
    """
    Decrypt a ciphertext with CryptoBox scheme under a given private key and
    sender's public key stored in certificate chain structure.

    :param cipher: Ciphertext to be decrypted.
    :type cipher: string
    :param private_key: Recipient's private key from
                        generate_cryptobox_keypair().
    :type private_key: bytes
    :param sender: Sender's subject.
    :type sender: string
    :param chain: Certificate chain containing the sender's certificate.
    :type chain: :class:`CertificateChain`

    :returns: Decrypted result.
    :rtype: bytes

    .. Raises:
       ValueError: An error occurred when private key is NULL or msg is NULL.
       LookupError: An error occurred when sender's public key has not been
       found in certificate chain.
    """
    if cipher is None:
        raise ValueError("Ciphertext is NULL.")
    if private_key is None:
        raise ValueError("Private key is NULL.")
    pub_key = None
    for sender_cert in chain.certs:
        if sender_cert.subject == sender:
            pub_key = sender_cert.subject_enc_key
            break
    if pub_key is None:
        raise LookupError('Sender\'s public key has not been found.')
    nonce = cipher[:24]
    cipher = cipher[24:]
    return crypto_box_curve25519xsalsa20poly1305_open(cipher, nonce, pub_key,
                                                      private_key)
