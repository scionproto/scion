crypto library usage
=====

Library Features:

- AES-CBC-MAC wrapper for Opaque field generation and verification for data packet.
- ED29915 wrapper for signature generation and verificaiton for beacon generation/propagation.
- PRNG wrapper (in case we might need it somewhere)
- Hash construction from AES Block ciphers (based on pycypto, will be replaced by AESNI in near future)
- ECDH encryption based on Curve25519.

Install necessary 3rd party library
========

Requirement:

1. Install [pycrypto](https://pypi.python.org/pypi/pycrypto) for symmetric cryptography.
- Download source tarball from the website, the newest verison is 2.6.1 now.
- Untar the source and run **python setup.py build**.
- Then run **python setup.py install** to install the library.


Todo
========
1. Replace AES operation with native AESNI instruction if underlying machines have supports.
