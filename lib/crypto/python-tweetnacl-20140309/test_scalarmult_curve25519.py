# 20140105
# Jan Mojzis
# Public domain.

import nacl

def scalarmult_curve25519_test1():
        """
        """

        sk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        r  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        pk = nacl.crypto_scalarmult_curve25519_base(nacl._fromhex(sk))
        if pk != nacl._fromhex(r):
                raise ValueError("invalid crypto_scalarmult_curve25519_base result")


def scalarmult_curve25519_test2():
        """
        """

        sk = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        r  = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        pk = nacl.crypto_scalarmult_curve25519_base(nacl._fromhex(sk))
        if pk != nacl._fromhex(r):
                raise ValueError("invalid crypto_scalarmult_curve25519_base result")


def scalarmult_curve25519_test3():
        """
        """

        alicesk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        bobpk   = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        r       = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        x = nacl.crypto_scalarmult_curve25519(nacl._fromhex(alicesk), nacl._fromhex(bobpk))
        if x != nacl._fromhex(r):
                raise ValueError("invalid crypto_scalarmult_curve25519 result")


def scalarmult_curve25519_constant_test():
        """
        """

        if nacl.crypto_scalarmult_curve25519_BYTES != 32:
                raise ValueError("invalid crypto_scalarmult_curve25519_BYTES")
        if nacl.crypto_scalarmult_curve25519_SCALARBYTES != 32:
                raise ValueError("invalid crypto_scalarmult_curve25519_SCALARBYTES")
        x = nacl.crypto_scalarmult_curve25519
        x = nacl.crypto_scalarmult_curve25519_base
        x = nacl.crypto_scalarmult_curve25519_IMPLEMENTATION
        x = nacl.crypto_scalarmult_curve25519_VERSION

def run():
        "'"
        "'"

        scalarmult_curve25519_test1()
        scalarmult_curve25519_test2()
        scalarmult_curve25519_test3()
        scalarmult_curve25519_constant_test()


if __name__ == '__main__':
        run()
