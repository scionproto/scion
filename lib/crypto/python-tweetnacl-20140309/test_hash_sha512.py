# 20140105
# Jan Mojzis
# Public domain.

import sys
import nacl

try:
        from sys import version_info
except ImportError:
        _pyversion = 1
else:
        _pyversion = version_info[0]


def _strbytes(x = []):
        """
        """

        if _pyversion < 3:
                data = ""
                for i in range(0, len(x)):
                        data = "%s%s" % (data, chr(x[i]))
        else:
                data = bytes(x)
        return data


def hash_sha512_mc_test():
        """
        NIST SHAVS 
        pseudorandomly generated messages (monte carlo) test
        """

        r = "dc13a41114a59c0bedba376d1afed10fda5be9febd68e0acaa9454007c8284845213cd05945a29ac1149ab0eb6c4714998614b79d6ca00648c9aba6b2335f0b3"
        seed = [
                0x41, 0x15, 0x63, 0xc9, 0x97, 0x5d, 0xeb, 0x4f,
                0xe8, 0x02, 0x76, 0x83, 0x0e, 0x83, 0x53, 0x04,
                0x82, 0x8a, 0x5c, 0xd8, 0x7c, 0x79, 0x34, 0xa5,
                0x5c, 0x45, 0xcc, 0x23, 0x49, 0x87, 0x2c, 0xd1,
                0x18, 0xd0, 0x70, 0xe7, 0x6f, 0x3d, 0x10, 0x8c,
                0x2a, 0x4c, 0x65, 0x4a, 0xfd, 0xee, 0x69, 0xbf,
                0x5b, 0xde, 0xbf, 0x95, 0x97, 0x30, 0xf3, 0xb4,
                0x4a, 0x2d, 0x02, 0xb5, 0xf4, 0x5e, 0x1d, 0x9a
        ]
        MD = list(range(0, 1003 * nacl.crypto_hash_sha512_BYTES))

        for j in range(0, 100):
                for i in range(0, len(seed)):
                        MD[0 * nacl.crypto_hash_sha512_BYTES + i] = seed[i]
                        MD[1 * nacl.crypto_hash_sha512_BYTES + i] = seed[i]
                        MD[2 * nacl.crypto_hash_sha512_BYTES + i] = seed[i]
                for i in range(3, 1003):
                        a = (i - 3) * nacl.crypto_hash_sha512_BYTES;
                        b = (i - 0) * nacl.crypto_hash_sha512_BYTES;
                        data = _strbytes(MD[a:b])
                        h = nacl.crypto_hash_sha512(data)
                        for k in range(0, nacl.crypto_hash_sha512_BYTES):
                                if type(h[k]) == type(''):
                                        MD[i * nacl.crypto_hash_sha512_BYTES + k] = ord(h[k])
                                else:
                                        MD[i * nacl.crypto_hash_sha512_BYTES + k] = h[k]

                for i in range(0, len(seed)):
                        seed[i]                                   = MD[1002 * nacl.crypto_hash_sha512_BYTES + i]
                        MD[j * nacl.crypto_hash_sha512_BYTES + i] = MD[1002 * nacl.crypto_hash_sha512_BYTES + i]

        if _strbytes(seed) != nacl._fromhex(r):
                raise ValueError("monte-carlo test failed")

def hash_sha512_constant_test():
        """
        """

        if nacl.crypto_hash_sha512_BYTES != 64:
                raise ValueError("invalid crypto_hash_sha512_BYTES")
        x = nacl.crypto_hash_sha512_VERSION
        x = nacl.crypto_hash_sha512_IMPLEMENTATION


def run():
        """
        """

        #main
        hash_sha512_mc_test()
        hash_sha512_constant_test()

if __name__ == '__main__':
        run()
