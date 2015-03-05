# Copyright 2014 ETH Zurich

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`asymcrypto` --- SCION asymmetric crypto functions
===========================================
"""

from lib.crypto.nacl import crypto_sign_ed25519_keypair
from lib.crypto.nacl import crypto_box_curve25519xsalsa20poly1305_keypair
from lib.crypto.nacl import crypto_sign_ed25519
from lib.crypto.nacl import crypto_sign_ed25519_open
from lib.crypto.nacl import crypto_box_curve25519xsalsa20poly1305
from lib.crypto.nacl import crypto_box_curve25519xsalsa20poly1305_open
from lib.crypto.nacl import randombytes
from lib.crypto.certificate import *
import base64

def generate_signature_keypair():
    """
    Generates a key pair for ed25519 signature scheme and returns the pair in
    base64 format strings.

    Returns:
        A pair (sk_ascii, vk_ascii), containing signing key (sk_ascii) and
        verifying key (vk_ascii).
    """
    (verifying_key, signing_key) = crypto_sign_ed25519_keypair()
    sk_ascii = base64.standard_b64encode(signing_key).decode('ascii')
    vk_ascii = base64.standard_b64encode(verifying_key).decode('ascii')
    return (sk_ascii, vk_ascii)

def generate_cryptobox_keypair():
    """
    Generates a key pair for CryptoBox scheme (basically it is a public-key
    based encryption scheme) and returns the pair in base64 format strings.
    The CryptoBox scheme constructs public-key based encryption involving ECDH
    over Curve 25519, stream cipher xsalsa20, and message authentication code
    poly1305.

    Returns:
        A key pair (pri_ascii, pub_ascii), containing private key for decryption
        (pri_ascii) and public key for encryption (pub_ascii).
    """
    (public_key, private_key) = crypto_box_curve25519xsalsa20poly1305_keypair()
    pri_ascii = base64.standard_b64encode(private_key).decode('ascii')
    pub_ascii = base64.standard_b64encode(public_key).decode('ascii')
    return (pri_ascii, pub_ascii)

def sign(msg, signing_key):
    """
    Signs a message with a given signing key and returns the signature.

    Args:
        msg: Message to be signed, as a bytes object.
        signing_key: Signing key from generate_signature_keypair(), as a base64
        encoded string.

    Returns:
        Packed message with original plaintext attached with corresponding
        ed25519 signature, as a base64-encoded string.
    """
    key = base64.b64decode(signing_key)
    msg_with_sig = crypto_sign_ed25519(msg, key)
    msg_with_sig = base64.standard_b64encode(msg_with_sig).decode('ascii')
    return msg_with_sig


def verify(msg_with_sig, subject, chain, roots, root_cert_version):
    """
    Verifies whether the packed message with attached signature is validly
    signed by a particular subject belonging a valid certificate chain.

    Args:
        msg_with_sig: Packed message attached with signature, as a base64
        encoded string.
        subject: Subject indicating the signing entity, as a string.
        chain: Certificate chain containing the signing entity's certificate.
        roots: Dictionary containing the root certificates.
        root_cert_version: Version of the root certificate which signed the
        last certificate in the certificate chain, as an integer.

    Returns:
        Boolean result whether the verification is successful or not.

    Raises:
        Exception: An exception occurred when certificate chain invalid.
        LookupError: An error occurred when signer's public key has not found in
        certificate chain.
    """
    if not chain.verify(subject, roots, root_cert_version):
        raise Exception('The certificate chain is invalid.')
    pub_key = None
    for signer_cert in chain.certs:
        if signer_cert.subject == subject:
            pub_key = signer_cert.subject_pub_key
            break
    if pub_key is None:
        raise LookupError('Signer\'s public key has not been found.')
    verifying_key = base64.b64decode(pub_key)
    try:
        crypto_sign_ed25519_open(base64.b64decode(msg_with_sig), verifying_key)
        return True
    except:
        logging.warning('Invalid signature.')
        return False

def encrypt(msg, private_key, recipient, chain):
    """
    Encrypts a message with CryptoBox scheme under a given private key and
    recipient's public key stored in certificate chain structure.

    Args:
        msg: Plaintext to be encrypted, as a bytes object.
        private_key: Sender's private key from generate_cryptobox_keypair(), as
        a base64 encoded string.
        recipient: Recipient's subject, as a string.
        chain: Certificate chain containing the recipient's certificate.

    Returns:
        Protected ciphertext, as a base64-encoded string.

    Raises:
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
    pub_key = base64.b64decode(pub_key)
    priv_key = base64.b64decode(private_key)
    nonce = randombytes(24)
    cipher = nonce + crypto_box_curve25519xsalsa20poly1305(msg, nonce, pub_key,
                                                           priv_key)
    return base64.standard_b64encode(cipher).decode('ascii')


def decrypt(cipher, private_key, sender, chain):
    """
    Decrypts a ciphertext with CryptoBox scheme under a given private key and
    sender's public key stored in certificate chain structure.

    Args:
        cipher: Plaintext to be encrypted, as a base64-encoded string.
        private_key: Recipient's private key from generate_cryptobox_keypair(),
        as a base64 encoded string.
        sender: Sender's subject, as a string.
        chain: Certificate chain containing the sender's certificate.

    Returns:
        Decrypted result, as a bytes object.

    Raises:
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
    pub_key = base64.b64decode(pub_key)
    priv_key = base64.b64decode(private_key)
    cipher = base64.b64decode(cipher)
    nonce = cipher[:24]
    cipher = cipher[24:]
    return crypto_box_curve25519xsalsa20poly1305_open(cipher, nonce, pub_key,
                                                      priv_key)
