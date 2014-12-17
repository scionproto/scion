# 20140106
# Jan Mojzis
# Public domain.

import nacl

def stream_salsa20_test():
        """
        """

        r = "2bd8e7db6877539e4f2b295ee415cd378ae214aa3beb3e08e911a5bd4a25e6ac16ca283c79c34c08c99f7bdb560111e8cac1ae65eea08ac384d7a591461ab6e3"
        k = "dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4"
        n = "8219e0036b7a0b37"

        c = nacl.crypto_stream_salsa20(4194304, nacl._fromhex(n), nacl._fromhex(k))
        h = nacl.crypto_hash_sha512(c)

        if h != nacl._fromhex(r):
                raise ValueError("unexpected result")


def stream_salsa20_constant_test():
        """
        """
        
        if nacl.crypto_stream_salsa20_KEYBYTES != 32:
                raise ValueError("invalid crypto_stream_salsa20_KEYBYTES")
        if nacl.crypto_stream_salsa20_NONCEBYTES != 8:
                raise ValueError("invalid crypto_stream_salsa20_NONCEBYTES")
        x = nacl.crypto_stream_salsa20
        x = nacl.crypto_stream_salsa20_IMPLEMENTATION
        x = nacl.crypto_stream_salsa20_VERSION
        x = nacl.crypto_stream_salsa20_xor


def run():
        "'"
        "'"
        stream_salsa20_test()
        stream_salsa20_constant_test()

if __name__ == '__main__':
        run()
