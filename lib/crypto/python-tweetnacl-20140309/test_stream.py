# 20140106
# Jan Mojzis
# Public domain.

import nacl


def stream_test():
        """
        """


        mlen = 0
        while 1:
                mlen = mlen + 1 + int(mlen / 16)

                if  mlen > 10000:
                        break

                m = nacl.randombytes(mlen)
                n = nacl.randombytes(nacl.crypto_stream_NONCEBYTES)
                k = nacl.randombytes(nacl.crypto_stream_KEYBYTES)
                c = nacl.crypto_stream_xor(m, n, k)
                m1 = nacl.crypto_stream_xor(c, n, k)

                if m != m1:
                        raise ValueError("crypto_stream_xor problem")


def stream_bad_test():
        """
        """

        n = nacl.randombytes(nacl.crypto_stream_NONCEBYTES);
        k = nacl.randombytes(nacl.crypto_stream_KEYBYTES);
        clen = 1
        m = nacl.randombytes(clen);

        bad = []
        tmp = {"clen":clen, "m":m, "k":k, "n":n}
        tmp["n"] = nacl.randombytes(nacl.crypto_stream_NONCEBYTES + 1)
        bad.append(tmp)
        tmp = {"clen":clen, "m":m, "k":k, "n":n}
        tmp["n"] = nacl.randombytes(nacl.crypto_stream_NONCEBYTES - 1)
        bad.append(tmp)
        tmp = {"clen":clen, "m":m, "k":k, "n":n}
        tmp["n"] = 0
        bad.append(tmp)
        tmp = {"clen":clen, "m":m, "k":k, "n":n}
        tmp["k"] = nacl.randombytes(nacl.crypto_stream_KEYBYTES + 1)
        bad.append(tmp)
        tmp = {"clen":clen, "m":m, "k":k, "n":n}
        tmp["k"] = nacl.randombytes(nacl.crypto_stream_KEYBYTES - 1)
        bad.append(tmp)
        tmp = {"clen":clen, "m":m, "k":k, "n":n}
        tmp["k"] = 0
        bad.append(tmp)
        tmp = {"clen":clen, "m":m, "k":k, "n":n}
        tmp["m"] = 0
        tmp["clen"] = -1
        bad.append(tmp)
        tmp = {"clen":clen, "m":m, "k":k, "n":n}
        tmp["m"] = 0
        tmp["clen"] = m
        bad.append(tmp)

        for tmp in bad:

                try:
                        nacl.crypto_stream_xor(tmp["m"], tmp["n"], tmp["k"])
                except:
                        pass
                else:
                        raise Exception("crypto_stream_xor accepts incorrect input data")

                try:
                        nacl.crypto_stream(tmp["clen"], tmp["n"], tmp["k"])
                except:
                        pass
                else:
                        raise Exception("crypto_stream accepts incorrect input data")



def stream_constant_test():
        """
        """

        x = nacl.crypto_stream
        x = nacl.crypto_stream_IMPLEMENTATION
        x = nacl.crypto_stream_KEYBYTES
        x = nacl.crypto_stream_NONCEBYTES
        x = nacl.crypto_stream_PRIMITIVE
        x = nacl.crypto_stream_VERSION
        x = nacl.crypto_stream_xor

def run():
        "'"
        "'"
        stream_bad_test()
        stream_test()
        stream_constant_test()

if __name__ == '__main__':
        run()


