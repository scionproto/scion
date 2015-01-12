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



def secretbox_bad_test():
        """
        """

        n = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES);
        k = nacl.randombytes(nacl.crypto_secretbox_KEYBYTES);
        m = nacl.randombytes(1);

        c = nacl.crypto_secretbox(m, n, k)


        #save exception string
        cx = nacl._randreplace(c)
        exc_string = ""
        try:
                nacl.crypto_secretbox_open(cx, n, k)
        except:
                exc_string = exc()

        bad = []
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["n"] = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES + 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["n"] = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES - 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["n"] = 0
        bad.append(tmp)
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["k"] = nacl.randombytes(nacl.crypto_secretbox_KEYBYTES + 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["k"] = nacl.randombytes(nacl.crypto_secretbox_KEYBYTES - 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["k"] = 0;
        bad.append(tmp)
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["m"] = 0
        tmp["c"] = 0
        bad.append(tmp)

        for tmp in bad:

                try:
                        nacl.crypto_secretbox(tmp["m"], tmp["n"], tmp["k"])
                except:
                        pass
                else:
                        raise Exception("crypto_secretbox accepts incorrect input data")

                try:
                        nacl.crypto_secretbox_open(tmp["c"], tmp["n"], tmp["k"])
                except:
                        if exc_string == exc():
                                raise
                else:
                        raise Exception("crypto_secretbox accepts incorrect input data")

def secretbox_test():
        """
        """

        mlen = 0
        while 1:
                mlen = mlen + 1 + int(mlen / 16)

                if  mlen > 10000:
                        break

                n = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES);
                k = nacl.randombytes(nacl.crypto_secretbox_KEYBYTES);
                m = nacl.randombytes(mlen);
        
                c = nacl.crypto_secretbox(m, n, k)
                m1 = nacl.crypto_secretbox_open(c, n, k)

                if m != m1:
                        raise ValueError("bad decryption")

                n1 = nacl._randreplace(n)
                try:
                        m1 = nacl.crypto_secretbox_open(c, n1, k)
                except:
                        pass
                else:
                        raise ValueError("forgery")

                c1 = nacl._randreplace(c)
                try:
                        m1 = nacl.crypto_secretbox_open(c1, n, k)
                except:
                        pass
                else:
                        raise ValueError("forgery")



def secretbox_constant_test():
        """
        """

        x = nacl.crypto_secretbox
        x = nacl.crypto_secretbox_BOXZEROBYTES
        x = nacl.crypto_secretbox_IMPLEMENTATION
        x = nacl.crypto_secretbox_KEYBYTES
        x = nacl.crypto_secretbox_NONCEBYTES
        x = nacl.crypto_secretbox_PRIMITIVE
        x = nacl.crypto_secretbox_VERSION
        x = nacl.crypto_secretbox_ZEROBYTES
        x = nacl.crypto_secretbox_open


def run():
        """
        """

        #main
        secretbox_bad_test()
        secretbox_test()
        secretbox_constant_test();


if __name__ == '__main__':
        run()
