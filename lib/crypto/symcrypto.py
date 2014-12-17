"""
symcrypto.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from python_sha3 import *
from aes import *
from gcm import *
import os, struct

class CryptoException(Exception):
    """Custom error Class used in the Crypto implementation"""
    def __init__(self, value):
    	self.value = value
    def __str__(self):
    	return repr(self.value)
    	

def Hash(data, algo):
    """ 
    Hash function with given data and supported algorithm options.
    
    @param data: a string object for symmetric key to encrypt data.
    @param algo: a string object for supported SHA3 algorithm, including
        SHA3-224, SHA3-256, SHA3-384, and SHA3-512.
    @return: the hash output, as a byte string.
    """
    if data == None:
    	raise CryptoException.CryptoException("Input data is NULL.")
    	return
    if algo == 'SHA3-224':
    	return sha3_224(data).hexdigest()
    elif algo == 'SHA3-256':
    	return sha3_256(data).hexdigest()
    elif algo == 'SHA3-384':
    	return sha3_384(data).hexdigest()
    elif algo == 'SHA3-512':
    	return sha3_512(data).hexdigest()
    else:
    	raise CryptoException.CryptoException("Input hash algorithm does not support.")
    	return

def MACObject(key):
    """ 
    Message Authentication Code Generator with given data and symmetric key.
    
    @param key: a byte object to represent symmetric key for MAC authenticator.
    @return: the reusable MAC authenticator.
    """
    if key == None:
    	raise CryptoException.CryptoException("Input data is NULL.")
    	return
    else: 
    	return CBCMAC(key, len(key))

def MACCompute(engine, msg):
    """ 
    Message Authentication Code Computation with preallocated authenticator and input message.
    
    @param engine: the MAC authenticator object. 
    @param msg: a string object to compute MAC value of data.
    @return: the MAC output, as a byte string.
    """
    if engine == None:
    	raise CryptoException.CryptoException("MAC authenticator is NULL.")
    	return
    else:
    	mac = engine.GenMAC(msg)
    	return struct.pack('B' * len(mac), *mac)

def MACVerify(engine, msg, rmac):
    """ 
    Message Authentication Code Verification with preallocated authenticator,
    	given message, and corresponding MAC.
    
    @param engine: the MAC authenticator object. 
    @param msg: a string object to compute MAC value of data.
    @param rmac: a byte string represents received MAC value of msg.
    @return: verification result, as a boolean value.
    """
    if engine == None:
    	raise CryptoException.CryptoException("MAC authenticator is NULL.")
    	return False
    else:
    	mac = engine.GenMAC(msg)
    	mac = struct.pack('B' * len(mac), *mac)
    	return mac == rmac

def AuthenEncrypt(key, msg, iv, auth):
    """ 
    Message Encryption using AES-GCM Algorithm with given key, plaintext, 
    	initialized vector, and authentication data.
    
    @param key: a byte string represents symmetric key for encryption.
    @param msg: a byte string object to be encrypted.
    @param auth: a byte string for authentication.
    @param iv: a byte string as initialized vector.
    @return: a concatenated cipher (c, t) where c is protected cipher
    	and t is authenticated tag.
    """
    c, t = gcm_encrypt(key, iv, msg, auth)
    return c+t

def AuthenDecrypt(key, cipher, iv, auth):
    """ 
    Message Decryption using AES-GCM Algorithm with given cipher and initialized vector.
    
    @param key: a byte string represents symmetric key for decryption.
    @param cipher: a byte string cipher to be decrypted.
    @param iv: a byte string as initialized vector.
    @param auth: a byte string for authentication.
    @return: decrypted result, as a byte string. If authentication fails, raise an
    	exception to abort.
    """
    ciphertext = cipher[:-16]
    tag = cipher[-16:]
    d = gcm_decrypt(key, iv, ciphertext, auth, tag)
    return d

def GenRandomByte(len):
    """Generates random bytes of length `size`.
    
    @param len: length which is greater than zero.
    @return: the Random output, as a byte string.
    """
    if len>0:
    	return os.urandom(len)
    else:
    	emsg = 'Invalid len, %s. Should be greater than 0.'
    	raise (ValueError, emsg % len)