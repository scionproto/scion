# 20140106
# Jan Mojzis
# Public domain.

import sys
import nacl

def exc():
        """
        """

        a, b, c = sys.exc_info()
        return b



def sign_bad_test():
        """
        """

        (pk, sk) = nacl.crypto_sign_keypair()
        if len(pk) != nacl.crypto_sign_PUBLICKEYBYTES:
                raise ValueError("invalid crypto_sign_keypair public-key length")
        if len(sk) != nacl.crypto_sign_SECRETKEYBYTES:
                raise ValueError("invalid crypto_sign_keypair secret-key length")

        m = nacl.randombytes(1)
        sm = nacl.crypto_sign(m, sk)

        #save exception string
        smx = nacl._randreplace(sm)
        exc_string = ""
        try:
                nacl.crypto_sign_open(smx, pk)
        except:
                exc_string = exc()

        ss = (
                nacl.randombytes(nacl.crypto_sign_SECRETKEYBYTES + 1),
                nacl.randombytes(nacl.crypto_sign_SECRETKEYBYTES - 1),
                0
        )
        pp = (
                nacl.randombytes(nacl.crypto_sign_PUBLICKEYBYTES + 1),
                nacl.randombytes(nacl.crypto_sign_PUBLICKEYBYTES - 1),
                0
        )

        for s in ss:
                try:
                        sm = nacl.crypto_sign(m, s)
                except:
                        pass
                else:
                        raise Exception("crypto_sign accepts incorrect input data")

        for p in pp:
                try:
                        nacl.crypto_sign_open(sm, p)
                except:
                        if exc_string == exc():
                                raise
                else:
                        raise Exception("crypto_sign_open accepts incorrect input data")

        try:
                sm = nacl.crypto_sign(0, sk)
        except:
                pass
        else:
                raise Exception("crypto_sign accepts incorrect input data")

        try:
                nacl.crypto_sign_open(0, pk)
        except:
                if exc_string == exc():
                        raise
        else:
                raise Exception("crypto_sign_open accepts incorrect input data")


def sign_test():
        """
        """

        mlen = 0
        while 1:
                mlen = mlen + 1 + int(mlen / 16)
        
                if  mlen > 10000:
                        break

                (pk, sk) = nacl.crypto_sign_keypair()
                m = nacl.randombytes(mlen)
                sm = nacl.crypto_sign(m, sk)
                t = nacl.crypto_sign_open(sm, pk)

                sm1 = nacl._randreplace(sm)
                try:
                        t1 = nacl.crypto_sign_open(sm1, pk)
                except:
                        pass
                else:
                        raise ValueError("forgery")

                if m != t:
                        raise ValueError("crypto_sign_open does not match contents")


def sign_constant_test():
        """
        """

        x = nacl.crypto_sign
        x = nacl.crypto_sign_BYTES
        x = nacl.crypto_sign_IMPLEMENTATION
        x = nacl.crypto_sign_PRIMITIVE
        x = nacl.crypto_sign_PUBLICKEYBYTES
        x = nacl.crypto_sign_SECRETKEYBYTES
        x = nacl.crypto_sign_VERSION
        x = nacl.crypto_sign_keypair
        x = nacl.crypto_sign_open

def run():
        """
        """
        sign_bad_test()
        sign_test()
        sign_constant_test()


if __name__ == '__main__':
        run()

