# 20140105
# Jan Mojzis
# Public domain.

import nacl

def box_curve25519xsalsa20poly1305_constant_test():
        """
        """

        if nacl.crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES != 32:
                raise ValueError("invalid crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES")
        if nacl.crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES != 32:
                raise ValueError("invalid crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES")
        if nacl.crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES != 32:
                raise ValueError("invalid crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES")
        if nacl.crypto_box_curve25519xsalsa20poly1305_NONCEBYTES != 24:
                raise ValueError("invalid crypto_box_curve25519xsalsa20poly1305_NONCEBYTES")
        if nacl.crypto_box_curve25519xsalsa20poly1305_ZEROBYTES != 32:
                raise ValueError("invalid crypto_box_curve25519xsalsa20poly1305_ZEROBYTES")
        if nacl.crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES != 16:
                raise ValueError("invalid crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES")

        x = nacl.crypto_box_curve25519xsalsa20poly1305
        x = nacl.crypto_box_curve25519xsalsa20poly1305_afternm
        x = nacl.crypto_box_curve25519xsalsa20poly1305_beforenm
        x = nacl.crypto_box_curve25519xsalsa20poly1305_keypair
        x = nacl.crypto_box_curve25519xsalsa20poly1305_open
        x = nacl.crypto_box_curve25519xsalsa20poly1305_open_afternm
        x = nacl.crypto_box_curve25519xsalsa20poly1305_IMPLEMENTATION
        x = nacl.crypto_box_curve25519xsalsa20poly1305_VERSION
        x = nacl.crypto_box_IMPLEMENTATION


def run():
        """
        """

        box_curve25519xsalsa20poly1305_constant_test()

if __name__ == '__main__':
        run()


