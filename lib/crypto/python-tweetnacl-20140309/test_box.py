# 20140105
# Jan Mojzis
# Public domain.

import sys
import nacl


def exc():
        """
        """
        
        a, b, c = sys.exc_info()
        return b


def box_bad_test():
        """
        """

        (pk, sk) = nacl.crypto_box_keypair()
        if len(pk) != nacl.crypto_box_PUBLICKEYBYTES:
                raise ValueError("invalid crypto_box_keypair public-key length")
        if len(sk) != nacl.crypto_box_SECRETKEYBYTES:
                raise ValueError("invalid crypto_box_keypair secret-key length")

        n = nacl.randombytes(nacl.crypto_box_NONCEBYTES);
        m = nacl.randombytes(1);

        c = nacl.crypto_box(m, n, pk, sk)

        #save exception string
        cx = nacl._randreplace(c)
        exc_string = ""
        try:
                nacl.crypto_box_open(cx, n, pk, sk)
        except:
                exc_string = exc()

        bad = []
        tmp = {"c":c, "m":m, "pk":pk, "sk":sk, "n":n}
        tmp["n"] = nacl.randombytes(nacl.crypto_box_NONCEBYTES + 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "pk":pk, "sk":sk, "n":n}
        tmp["n"] = nacl.randombytes(nacl.crypto_box_NONCEBYTES - 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "pk":pk, "sk":sk, "n":n}
        tmp["n"] = 0
        bad.append(tmp)
        tmp = {"m":m, "pk":pk, "sk":sk, "n":n}
        tmp = {"c":c, "m":m, "pk":pk, "sk":sk, "n":n}
        tmp["pk"] = nacl.randombytes(nacl.crypto_box_PUBLICKEYBYTES + 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "pk":pk, "sk":sk, "n":n}
        tmp["pk"] = nacl.randombytes(nacl.crypto_box_PUBLICKEYBYTES - 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "pk":pk, "sk":sk, "n":n}
        tmp["pk"] = 0
        bad.append(tmp)
        tmp = {"c":c, "m":m, "pk":pk, "sk":sk, "n":n}
        tmp["sk"] = nacl.randombytes(nacl.crypto_box_SECRETKEYBYTES + 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "pk":pk, "sk":sk, "n":n}
        tmp["sk"] = nacl.randombytes(nacl.crypto_box_SECRETKEYBYTES - 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "pk":pk, "sk":sk, "n":n}
        tmp["sk"] = 0
        bad.append(tmp)
        tmp = {"c":c, "m":m, "pk":pk, "sk":sk, "n":n}
        tmp["m"] = 0
        tmp["c"] = 0
        bad.append(tmp)

        for tmp in bad:
                try:
                        nacl.crypto_box(tmp["m"], tmp["n"], tmp["pk"], tmp["sk"])
                except:
                        pass
                else:
                        raise Exception("crypto_box accepts incorrect input data")
                try:
                        nacl.crypto_box_open(tmp["c"], tmp["n"], tmp["pk"], tmp["sk"])
                except:
                        if exc_string == exc():
                                raise
                else:
                        raise Exception("crypto_box_open accepts incorrect input data")

                try:
                        k = nacl.crypto_box_beforenm(tmp["pk"], tmp["sk"])
                        if len(k) != nacl.crypto_box_BEFORENMBYTES:
                                raise ValueError("invalid crypto_box_beforenm beforenm-key length")
                        nacl.crypto_box_afternm(tmp["m"], tmp["n"], k)
                except:
                        pass
                else:
                        raise Exception("crypto_box_afternm accepts incorrect input data")

                try:
                        k = nacl.crypto_box_beforenm(tmp["pk"], tmp["sk"])
                        if len(k) != nacl.crypto_box_BEFORENMBYTES:
                                raise ValueError("invalid crypto_box_beforenm beforenm-key length")
                        nacl.crypto_box_open_afternm(tmp["c"], tmp["n"], k)
                except:
                        if exc_string == exc():
                                raise
                else:
                        raise Exception("crypto_box_open_afternm accepts incorrect input data")


def box_test():
        """
        """

        mlen = 0
        while 1:
                mlen = mlen + 1 + int(mlen / 16)

                if  mlen > 10000:
                        break

                (alicepk,alicesk) = nacl.crypto_box_keypair();
                (bobpk,bobsk) = nacl.crypto_box_keypair();

                n = nacl.randombytes(nacl.crypto_box_NONCEBYTES);
                m = nacl.randombytes(mlen);

                c = nacl.crypto_box(m, n, alicepk, bobsk)
                m1 = nacl.crypto_box_open(c, n, bobpk, alicesk)

                if m != m1:
                        raise ValueError("bad decryption")

                n1 = nacl._randreplace(n)
                try:
                        m1 = nacl.crypto_box_open(c, n1, bobpk, alicesk)
                except:
                        pass
                else:
                        raise ValueError("forgery")

                c1 = nacl._randreplace(c)
                try:
                        m1 = nacl.crypto_box_open(c1, n, bobpk, alicesk)
                except:
                        pass
                else:
                        raise ValueError("forgery")

def box_test2():
        """
        """

        mlen = 0
        while 1:
                mlen = mlen + 1 + int(mlen / 16)

                if  mlen > 10000:
                        break


                (alicepk,alicesk) = nacl.crypto_box_keypair();
                (bobpk,bobsk) = nacl.crypto_box_keypair();

                n = nacl.randombytes(nacl.crypto_box_NONCEBYTES);
                m = nacl.randombytes(mlen);

                bobk   = nacl.crypto_box_beforenm(alicepk, bobsk)
                alicek = nacl.crypto_box_beforenm(bobpk, alicesk)

                c  = nacl.crypto_box_afternm(m,n,bobk)
                m1 = nacl.crypto_box_open_afternm(c, n, alicek)

                if m != m1:
                        raise ValueError("bad decryption")

                n1 = nacl._randreplace(n)
                try:
                        m1 = nacl.crypto_box_open_afternm(c, n1, alicek)
                except:
                        pass
                else:
                        raise ValueError("forgery")

                c1 = nacl._randreplace(c)
                try:
                        m1 = nacl.crypto_box_open_afternm(c1, n, alicek)
                except:
                        pass
                else:
                        raise ValueError("forgery")


def box_constant_test():
        """
        """

        x = nacl.crypto_box_BEFORENMBYTES
        x = nacl.crypto_box_BOXZEROBYTES
        x = nacl.crypto_box_IMPLEMENTATION
        x = nacl.crypto_box_NONCEBYTES
        x = nacl.crypto_box_PRIMITIVE
        x = nacl.crypto_box_PUBLICKEYBYTES
        x = nacl.crypto_box_SECRETKEYBYTES
        x = nacl.crypto_box_VERSION
        x = nacl.crypto_box_ZEROBYTES
        x = nacl.crypto_box
        x = nacl.crypto_box_afternm
        x = nacl.crypto_box_beforenm
        x = nacl.crypto_box_keypair
        x = nacl.crypto_box_open
        x = nacl.crypto_box_open_afternm



def run():
        """
        """

        box_bad_test();
        box_test()
        box_test2()
        box_constant_test()

if __name__ == '__main__':
        run()


