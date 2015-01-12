# 20140106
# Jan Mojzis
# Public domain.

import nacl

def sign_ed25519_test():
        """
        """

        pk =      "8f58d8bfb192d1d7e0c3998a8d5cb5effc922a0d7080e83be027ebf61495fd16"
        sk =      "7834095954aaa92c523a413fb6fa6be1d70f39305ae17012597d32599b8b6b2f"
        sk = sk + "8f58d8bfb192d1d7e0c3998a8d5cb5effc922a0d7080e83be027ebf61495fd16"
        m  =      "61686f6a0a"
        sm =      "ce1e15adc31747157d4460c17fb8ba45f36d0bbf51f9bb6bb9a1d24e448d9e8c"
        sm = sm + "366f7a8b5e2c69ba902e954619d8c18a47c56e4a289e8117ae9069717d846a01"
        sm = sm + "61686f6a0a"

        s = nacl.crypto_sign_ed25519(nacl._fromhex(m), nacl._fromhex(sk))

        if s != nacl._fromhex(sm):
                raise ValueError("invalid signature")

        t = nacl.crypto_sign_ed25519_open(s, nacl._fromhex(pk))
        if nacl._fromhex(m) != t:
                raise ValueError("crypto_sign_open does not match contents")

def sign_ed25519_constant_test():
        """
        """

        if nacl.crypto_sign_ed25519_BYTES != 64:
                raise ValueError("invalid crypto_sign_ed25519_BYTES")
        if nacl.crypto_sign_ed25519_PUBLICKEYBYTES != 32:
                raise ValueError("invalid crypto_sign_ed25519_PUBLICKEYBYTES")
        if nacl.crypto_sign_ed25519_SECRETKEYBYTES != 64:
                raise ValueError("invalid crypto_sign_ed25519_SECRETKEYBYTES")
        x = nacl.crypto_sign_ed25519
        x = nacl.crypto_sign_ed25519_IMPLEMENTATION
        x = nacl.crypto_sign_ed25519_VERSION
        x = nacl.crypto_sign_ed25519_keypair
        x = nacl.crypto_sign_ed25519_open


def run():
        """
        """
        sign_ed25519_test()
        sign_ed25519_constant_test()


if __name__ == '__main__':
        run()

