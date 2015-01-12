# 20140105
# Jan Mojzis
# Public domain.

import nacl

def hash_base_test():
        """
        """

        x = nacl.crypto_hash(nacl.randombytes(1))
        if (len(x) != nacl.crypto_hash_BYTES):
                raise ValueError("invalid crypto_hash output length")
                
        try:
                x = nacl.crypto_hash(0)
        except:
                pass
        else:
                raise Exception("crypto_hash accepts bad input data")


def hash_constant_test():
        """
        """

        x = nacl.crypto_hash
        x = nacl.crypto_hash_BYTES
        x = nacl.crypto_hash_PRIMITIVE
        x = nacl.crypto_hash_VERSION
        x = nacl.crypto_hash_IMPLEMENTATION

def run():
        """
        """

        #main
        hash_base_test()
        hash_constant_test()

if __name__ == '__main__':
        run()
