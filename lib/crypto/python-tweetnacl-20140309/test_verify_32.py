# 20140106
# Jan Mojzis
# Public domain.

import nacl

def verify_32_test():
        """
        """

        for x in range(0, 10):
                
                x = nacl.randombytes(nacl.crypto_verify_32_BYTES)
                y = x

                nacl.crypto_verify_32(x, y)

                y1 = nacl._randreplace(y)

                try:
                        nacl.crypto_verify_32(x, y1)
                except ValueError:
                        pass
                else:
                        raise ValueError("forgery")

def verify_32_constant_test():
        """
        """

        if nacl.crypto_verify_32_BYTES != 32:
                raise ValueError("invalid crypto_verify_32_BYTES")

        x = nacl.crypto_verify_32
        x = nacl.crypto_verify_32_BYTES
        x = nacl.crypto_verify_32_IMPLEMENTATION
        x = nacl.crypto_verify_32_VERSION


def run():
        "'"
        "'"
        verify_32_test()
        verify_32_constant_test()

if __name__ == '__main__':
        run()

