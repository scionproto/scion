# 20140105
# Jan Mojzis
# Public domain.

import nacl


def scalarmult_bad_test():
        """
        """

        sk = nacl.randombytes(nacl.crypto_scalarmult_SCALARBYTES)
        pk = nacl.crypto_scalarmult_base(sk);
        if len(pk) != nacl.crypto_scalarmult_BYTES:
                raise ValueError("invalid crypto_scalarmult_base output length")

        k = nacl.crypto_scalarmult(sk, pk)
        if len(k) != nacl.crypto_scalarmult_BYTES:
                raise ValueError("invalid crypto_scalarmult output length")

        ss = (
                nacl.randombytes(nacl.crypto_scalarmult_SCALARBYTES + 1),
                nacl.randombytes(nacl.crypto_scalarmult_SCALARBYTES - 1),
                0
        )
        pp = (
                nacl.randombytes(nacl.crypto_scalarmult_BYTES + 1),
                nacl.randombytes(nacl.crypto_scalarmult_BYTES - 1),
                0
        )
        for s in ss:
                try:
                        pk = nacl.crypto_scalarmult_base(s);
                except:
                        pass
                else:
                        raise Exception("crypto_scalarmult_base accepts incorrect input data")
                try:
                        k = nacl.crypto_scalarmult(s, pk);
                except:
                        pass
                else:
                        raise Exception("crypto_scalarmult accepts incorrect input data")
        for p in pp:
                try:
                        k = nacl.crypto_scalarmult(sk, p);
                except:
                        pass
                else:
                        raise Exception("crypto_scalarmult accepts incorrect input data")


def scalarmult_test():
        """
        """

        for i in range(0, 10):

                alicesk = nacl.randombytes(nacl.crypto_scalarmult_SCALARBYTES)
                alicepk = nacl.crypto_scalarmult_base(alicesk);

                bobsk = nacl.randombytes(nacl.crypto_scalarmult_SCALARBYTES)
                bobpk = nacl.crypto_scalarmult_base(bobsk);

                alicek = nacl.crypto_scalarmult(alicesk, bobpk)
                bobk   = nacl.crypto_scalarmult(bobsk, alicepk)

                if nacl.crypto_scalarmult(alicesk, bobpk) != nacl.crypto_scalarmult(bobsk, alicepk):
                        raise ValueError("crypto_scalarmult problem")


def scalarmult_constant_test():
        """
        """

        x = nacl.crypto_scalarmult
        x = nacl.crypto_scalarmult_base
        x = nacl.crypto_scalarmult_BYTES
        x = nacl.crypto_scalarmult_IMPLEMENTATION
        x = nacl.crypto_scalarmult_PRIMITIVE
        x = nacl.crypto_scalarmult_SCALARBYTES
        x = nacl.crypto_scalarmult_VERSION


def run():
        "'"
        "'"

        scalarmult_bad_test()
        scalarmult_test()
        scalarmult_constant_test()


if __name__ == '__main__':
        run()

