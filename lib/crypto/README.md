crypto library usage
=====

Library Features:

- Symmetric cryptography: AES-CBC and AES-CBC-MAC wrappers for Opaque field generation and verification for data packet.
- Asymmetric cryptography: Python tweetnacl wrappers for Asymmetric library support including ed25519 and public-key encryption scheme (curve25519xsalsa20poly1305).


Todo
========
1. Replace AES operation with native AESNI instruction if underlying machines have supports.
2. Implement fast PRNG generator based on AESNI.
3. Implement fast HASH based on AESNI.
4. Improve poly1305 algorithm based on AESNI.
