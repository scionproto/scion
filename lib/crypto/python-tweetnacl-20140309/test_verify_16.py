# 20140106
# Jan Mojzis
# Public domain.

import nacl

def verify_16_test():
        """
        """

        for x in range(0, 10):
                
                x = nacl.randombytes(nacl.crypto_verify_16_BYTES)
                y = x

                nacl.crypto_verify_16(x, y)

                y1 = nacl._randreplace(y)

                try:
                        nacl.crypto_verify_16(x, y1)
                except ValueError:
                        pass
                else:
                        raise ValueError("forgery")

def verify_16_constant_test():
        """
        """

        if nacl.crypto_verify_16_BYTES != 16:
                raise ValueError("invalid crypto_verify_16_BYTES")

        x = nacl.crypto_verify_16
        x = nacl.crypto_verify_16_BYTES
        x = nacl.crypto_verify_16_IMPLEMENTATION
        x = nacl.crypto_verify_16_VERSION


def run():
        "'"
        "'"
        verify_16_test()
        verify_16_constant_test()

if __name__ == '__main__':
        run()

