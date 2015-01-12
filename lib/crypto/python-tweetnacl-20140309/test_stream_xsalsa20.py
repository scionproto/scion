# 20140106
# Jan Mojzis
# Public domain.

import nacl


def stream_xsalsa20_test():
        """
        """

        r =     "2bd8e7db6877539e4f2b295ee415cd378ae214aa3beb3e08e911a5bd4a25e6ac"
        r = r + "16ca283c79c34c08c99f7bdb560111e8cac1ae65eea08ac384d7a591461ab6e3"
        k =     "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"
        n =     "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"

        c = nacl.crypto_stream_xsalsa20(4194304, nacl._fromhex(n), nacl._fromhex(k))
        h = nacl.crypto_hash_sha512(c)

        if h != nacl._fromhex(r):
                raise ValueError("unexpected result")


def stream_xsalsa20_test3():
        """
        """

        r = "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880"
        k = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"
        n = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"

        c = nacl.crypto_stream_xsalsa20(32, nacl._fromhex(n), nacl._fromhex(k))

        if c != nacl._fromhex(r):
                raise ValueError("unexpected result")

def stream_xsalsa20_test4():
        """
        """

        m =     "0000000000000000000000000000000000000000000000000000000000000000"
        m = m + "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc"
        m = m + "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31"
        m = m + "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde"
        m = m + "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864"
        m = m + "5e0705"

        r =     "0000000000000000000000000000000000000000000000000000000000000000"
        r = r + "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a"
        r = r + "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738"
        r = r + "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da"
        r = r + "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74"
        r = r + "e355a5"

        k =     "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"
        n =     "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"

        c = nacl.crypto_stream_xsalsa20_xor(nacl._fromhex(m), nacl._fromhex(n), nacl._fromhex(k))

        if c[32:] != nacl._fromhex(r)[32:]:
                raise ValueError("unexpected result")


def stream_xsalsa20_constant_test():
        """
        """
        
        if nacl.crypto_stream_xsalsa20_KEYBYTES != 32:
                raise ValueError("invalid crypto_stream_xsalsa20_KEYBYTES")
        if nacl.crypto_stream_xsalsa20_NONCEBYTES != 24:
                raise ValueError("invalid crypto_stream_xsalsa20_NONCEBYTES")
        x = nacl.crypto_stream_xsalsa20
        x = nacl.crypto_stream_xsalsa20_IMPLEMENTATION
        x = nacl.crypto_stream_xsalsa20_VERSION
        x = nacl.crypto_stream_xsalsa20_xor


def run():
        "'"
        "'"
        stream_xsalsa20_test()
        stream_xsalsa20_test3()
        stream_xsalsa20_test4()
        stream_xsalsa20_constant_test()

if __name__ == '__main__':
        run()
