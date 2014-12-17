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


def onetimeauth_bad_test():
        """
        """

        k = nacl.randombytes(nacl.crypto_onetimeauth_KEYBYTES)
        m = nacl.randombytes(1)
        a = nacl.crypto_onetimeauth(m, k)

        #save exception string
        exc_string = ""
        ax = nacl._randreplace(a)
        try:
                a = nacl.crypto_onetimeauth(ax, k)
        except:
                exc_string = exc()

        bad = []
        tmp = {"k":k, "m":m, "a":a}
        tmp["k"] = nacl.randombytes(nacl.crypto_onetimeauth_KEYBYTES + 1)
        bad.append(tmp)
        tmp = {"k":k, "m":m, "a":a}
        tmp["k"] = nacl.randombytes(nacl.crypto_onetimeauth_KEYBYTES - 1)
        bad.append(tmp)
        tmp = {"k":k, "m":m, "a":a}
        tmp["k"] = 0
        bad.append(tmp)
        tmp = {"k":k, "m":m, "a":a}
        tmp["m"] = 0
        tmp["a"] = 0
        bad.append(tmp)

        for tmp in bad:

                try:
                        nacl.crypto_onetimeauth(tmp["m"], tmp["k"])
                except:
                        pass
                else:
                        raise Exception("crypto_onetimeauth accepts incorrect input data")
                try:
                        nacl.crypto_onetimeauth_open(tmp["a"], tmp["k"])
                except:
                        if exc_string == exc():
                                raise
                else:
                        raise Exception("crypto_onetimeauth_open accepts incorrect input data")


def onetimeauth_test():
        """
        """

        return


        mlen = 0
        while 1:
                mlen = mlen + 1 + int(mlen / 16)

                if  mlen > 10000:
                        break

                k = nacl.randombytes(nacl.crypto_onetimeauth_KEYBYTES)
                m = nacl.randombytes(mlen)
                a = nacl.crypto_onetimeauth(m, k)
                nacl.crypto_onetimeauth_verify(a, m, k)

                if mlen < 1:
                        continue

                a1 = nacl._randreplace(a)
                try:
                        nacl.crypto_onetimeauth_verify(a1, m, k)
                except:
                        pass
                else:
                        raise ValueError("forgery")



def onetimeauth_constant_test():
        """
        """

        x = nacl.crypto_onetimeauth
        x = nacl.crypto_onetimeauth_verify
        x = nacl.crypto_onetimeauth_BYTES
        x = nacl.crypto_onetimeauth_IMPLEMENTATION
        x = nacl.crypto_onetimeauth_KEYBYTES
        x = nacl.crypto_onetimeauth_PRIMITIVE
        x = nacl.crypto_onetimeauth_VERSION


def run():
        """
        """

        onetimeauth_test()
        onetimeauth_bad_test()
        onetimeauth_constant_test()


if __name__ == '__main__':
        run()

