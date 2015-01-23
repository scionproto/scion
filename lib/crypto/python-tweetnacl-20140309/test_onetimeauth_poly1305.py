# 20140105
# Jan Mojzis
# Public domain.

import nacl

def onetimeauth_poly1305_test():
        """
        """

        k =     "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880"
        m =     "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a"
        m = m + "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738"
        m = m + "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da"
        m = m + "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74"
        m = m + "e355a5"
        r =     "f3ffc7703f9400e52a7dfb4b3d3305d9"

        a = nacl.crypto_onetimeauth_poly1305(nacl._fromhex(m), nacl._fromhex(k))
        if a != nacl._fromhex(r):
                raise ValueError("invalid authenticator")

def onetimeauth_poly1305_test2():
        """
        """

        k =     "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880"
        m =     "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a"
        m = m + "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738"
        m = m + "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da"
        m = m + "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74"
        m = m + "e355a5"
        a =     "f3ffc7703f9400e52a7dfb4b3d3305d9"

        nacl.crypto_onetimeauth_poly1305_verify(nacl._fromhex(a), nacl._fromhex(m), nacl._fromhex(k))

def onetimeauth_poly1305_constant_test():
        """
        """

        if nacl.crypto_onetimeauth_poly1305_BYTES != 16:
                raise ValueError("invalid crypto_onetimeauth_poly1305_BYTES")
        if nacl.crypto_onetimeauth_poly1305_KEYBYTES != 32:
                raise ValueError("invalid crypto_onetimeauth_poly1305_KEYBYTES")
        x = nacl.crypto_onetimeauth_poly1305
        x = nacl.crypto_onetimeauth_poly1305_IMPLEMENTATION
        x = nacl.crypto_onetimeauth_poly1305_VERSION
        x = nacl.crypto_onetimeauth_poly1305_verify


def run():
        """
        """
        onetimeauth_poly1305_test()
        onetimeauth_poly1305_test2()
        onetimeauth_poly1305_constant_test()


if __name__ == '__main__':
        run()
