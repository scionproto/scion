"""
asymcrypto.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from lib.crypto.nacl import *
from lib.crypto.certificates import *
import base64

def generate_keys():
    """
    Generates two pair of keys and returns them in base64 format.
    The first pair is for ed25519 signature scheme.
    The second pair is for public-key based encryption scheme
    (curve25519ecdh+xsalsa20+poly1305).
    Return a quadruple list contain (signing_key, verifyng_key, private_key,
    public_key)
    """
    (verifyng_key, signing_key) = crypto_sign_ed25519_keypair()
    (public_key, private_key) = crypto_box_curve25519xsalsa20poly1305_keypair()
    sk_ascii = base64.standard_b64encode(signing_key).decode('ascii')
    vk_ascii = base64.standard_b64encode(verifyng_key).decode('ascii')
    pri_ascii = base64.standard_b64encode(private_key).decode('ascii')
    pub_ascii = base64.standard_b64encode(public_key).decode('ascii')
    return (sk_ascii, vk_ascii, pri_ascii, pub_ascii)

def sign(msg, priv_key):
    """
    Signs a message with the given private key and returns the computed
    signature.

    @param msg: String message to sign.
    @param priv_key: Private key used to compute the signature.
    """
    msg = str.encode(msg)
    signing_key = base64.b64decode(priv_key)
    signature = crypto_sign_ed25519(msg, signing_key)
    signature = base64.standard_b64encode(signature).decode('ascii')
    return signature


def verify(pack, subject, chain, roots, root_cert_version):
    """
    Verifies whether the provided signature is the right one and if it was
    computed using a valid certificate chain.

    @param pack: String message concatenated with the signature to verify.
    @param subject: String containing the subject of the entity who signed the
        message.
    @param chain: Certificate chain containing the signing entity's certificate.
    @param roots: Dictionary containing the root certificates.
    @param root_cert_version: Version of the root certificate which signed the
        last certificate in the certificate chain.
    """
    if not chain.verify(subject, roots, root_cert_version):
        raise Exception("The certificate chain is invalid.")
        return False
    pub_key = None
    for signer_cert in chain.certs:
        if signer_cert.subject == subject:
            pub_key = signer_cert.subject_pub_key
            break
    if pub_key is None:
        raise Exception("Signer's public key not found.")
        return False
    verifying_key = base64.b64decode(pub_key)
    try:
        crypto_sign_ed25519_open(base64.b64decode(pack), verifying_key)
        return True
    except:
        logging.warning("The signature is not valid.")
        return False

def authenticated_encrypt(msg, priv_key, subject, chain):
    """
    Encrypts a message with the given private key and returns the computed
    cipher.
    
    @param msg: String message to encrypt.
    @param priv_key: Sender's private key used to encrypt the message.
    @param subject: String containing the subject of the entity who plans
        to decrypt the cipher.
    @param chain: Certificate chain containing the recipient entity's
        certificate.
    """
    if priv_key is None:
        raise Exception("Error: Private key is NULL.")
        return
    if msg is None:
        raise Exception("Error: Plaintext data is NULL.")
        return
    pub_key = None
    for recipient_cert in chain.certs:
        if recipient_cert.subject == subject:
            pub_key = recipient_cert.subject_enc_key
            break
    if pub_key is None:
        raise Exception("Recipient's public key not found.")
        return None
    pub_key = base64.b64decode(pub_key)
    priv_key = base64.b64decode(priv_key)
    nonce = randombytes(24)
    cipher = nonce + crypto_box_curve25519xsalsa20poly1305(msg, nonce, pub_key,
        priv_key)
    return base64.standard_b64encode(cipher).decode('ascii')


def authenticated_decrypt(cipher, priv_key, subject, chain):
    """
    Decrypts a cipher with the given private key and returns the plaintext.
    
    @param cipher: Base64 encoded cipher to decrypt.
    @param priv_key: Recipient's private key used to decrypt the message.
    @param subject: String containing the subject of the entity who encrypts the 
        message.
    @param chain: Certificate chain containing the sender entity's certificate.
    """
    if cipher is None:
        raise Exception("Error: Cipher data is NULL.")
        return
    if priv_key is None:
        raise Exception("Error: Private key is NULL.")
        return
    pub_key = None
    for sender_cert in chain.certs:
        if sender_cert.subject == subject:
            pub_key = sender_cert.subject_enc_key
            break
    if pub_key is None:
        raise Exception("Sender's public key not found.")
        return
    pub_key = base64.b64decode(pub_key)
    priv_key = base64.b64decode(priv_key)
    cipher = base64.b64decode(cipher)
    nonce = cipher[:24]
    cipher = cipher[24:]
    return crypto_box_curve25519xsalsa20poly1305_open(cipher, nonce, pub_key,
        priv_key)
