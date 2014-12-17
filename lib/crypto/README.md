crypto library usage
=====

Library Features:

- Symmetric cryptography: Crypto library provides Hash, MAC, and Block Cipher engine.
- Asymmetric cryptography: Crypto library provides Public-key encryption scheme and digital signature scheme.
- Short (and Fast) Signature: ed25519 signature wrappers from [python-tweetnacl](http://mojzis.com/software/python-tweetnacl/index.html).
- Public-Key Encryption/Decryption: CryptoBox scheme (ecdh over curve25519+xsalsa20+poly1305).
- Pure Keccak and AES cipher python script.
- SHA3 wrapper supported.
- AES-CGM/AES-CBC-MAC wrapper supported.

File Structure
=======

- **/certificates.py** Certificate generation and verification.
- **/asymcrypto.py** Asymmetric Crypto Utilities Wrapper.
- **/symcrypto.py** Symmetric Crypto Utilities Wrapper.
- **/python_sha3.py** SHA3 python implementation.
- **/aes.py** AES cipher and CBC-MAC implementation.
- **/gcm.py** AES-GCM implementation.
- **/nacl.py** NaCl library loader.
- **/python-tweetnacl-20140309/** Library source from from [python-tweetnacl](http://mojzis.com/software/python-tweetnacl/index.html).

Dependency
========
Build python-tweetnacl, you have to run `sh do` in python-tweetnacl folder.
Or you can execute scion.sh in root folder.
 

Todo
========
1. Replace AES operation with native AESNI instruction if underlying machines have supports.
