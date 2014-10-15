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

import sys, hashlib, binascii, struct, io

if sys.version_info[0] == 3:
	import io
else:
	import StringIO

# AES Cipher
from Crypto.Cipher import AES
from Crypto import Random

# PCKS#7 padding
def pkcs7padding(data):
	"""
	Pad input data with PKCS#7 bytes format (See RFC 5652) into 16-byte aligned blocks.
	"""
	l = len(data)
	if sys.version_info[0] == 3:
		output = io.StringIO()
	else:
		output = StringIO.StringIO()
	val = 16 - (l % 16)
	for _ in range(val): output.write('%02x' % val)
	padded_data = bytes(data) + binascii.unhexlify(output.getvalue())
	return padded_data

def pkcs7unpadding(encode):
	"""
	Strip PKCS#7 bytes from input data (See RFC 5652) back to original input.
	"""
	nl = len(encode)
	if sys.version_info[0] == 3:
		val = int(str(encode[-1]))
	else:
		val = int(binascii.hexlify(encode[-1]), 16)
	if val > 16: raise ValueError('Input is not padded or padding is corrupt')
	l = nl - val
	return encode[:l]


class SymCryptoUtil(object):
	"""
	Symmetric Cryptography Utility Class
	"""
	
	@staticmethod
	def CBCEncrypt(keybytes, iv, data):
		""" 
		AES CBC Cipher Encryption with given key, iv vector, and input bytes.
		
		@param keybytes: a string object for symmetric key to encrypt data.
		@param iv: a string object for initial vector.
		@param data: a byte string of plaintext.
		@return: the encrypted data, as a byte string.
		"""
		# PKCS#7 padding
		padded_data = pkcs7padding(data)
		# Encrypt, AES CBC Cipher
		cipher = AES.new(keybytes, AES.MODE_CBC, iv)
		encrypted = cipher.encrypt(bytes(padded_data))
		return encrypted
	
	@staticmethod
	def CBCDecrypt(keybytes, iv, data):
		""" 
		AES CBC Cipher Decryption with given key, iv vector, and cipher bytes.
		
		@param keybytes: a string object for symmetric key to decrypt data.
		@param iv: a string object for initial vector.
		@param data: a byte string of cipher.
		@return: the deciphered data, as a byte string.	
		"""
		# Decrypt, AES CBC Cipher
		cipher = AES.new(keybytes, AES.MODE_CBC, iv)
		decipher = cipher.decrypt(data)
		# PKCS#7 unpadding
		decipher = pkcs7unpadding(decipher)
		return decipher
		
	@staticmethod
	def CBCMAC(keybytes, data):
		"""
		CBC-MAC computation by a given input and a key to compute its MAC.
		
		@param keybytes: a string object for symmetric key to recompute MAC.
		@param data: a byte string of plaintext.
		@return mac: a received mac to validate integrity of input data.
		"""
		iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		cmac = SymCryptoUtil().CBCEncrypt(keybytes, iv, bytes(data))
		return cmac[-16:]
    
	@staticmethod
	def CBCMACVerify(keybytes, data, mac):
		"""
    	CBC-MAC verification by a given input, a key, and a received MAC.
    	
    	@param keybytes: a string object for symmetric key to recompute MAC.
    	@param data: a byte string of plaintext.
    	@param mac: a received mac to validate integrity of input data.
    	@return: Boolean value to indicate MAC verification result.
    	"""
		cmac = SymCryptoUtil().CBCMAC(keybytes, bytes(data))
		if cmac == mac:
			return True;
		else:
			return False;
	
	@staticmethod
	def GenerateRandom(len):
		"""
		GenerateRandom function produce len byte randomness. 
		
		@param len: byte length for randomness.
		@return: a len-byte random string.
		"""
		rndfile = Random.new()
		return rndfile.read(len)
	
	def test(self):
		print ("---AES-CBC-Cipher Test---")
		iv  = SymCryptoUtil().GenerateRandom(16)
		key = SymCryptoUtil().GenerateRandom(16)
		secret = SymCryptoUtil().GenerateRandom(16)
		print ("Plaintext: %s" % secret)
		cipher = SymCryptoUtil().CBCEncrypt(key, iv, secret)
		print ("AES-CBC-ENC(len = %d): %s" % (len(cipher), binascii.hexlify(cipher)))
		decipher = SymCryptoUtil().CBCDecrypt(key, iv, cipher)
		print ("AES-CBC-DEC: %s" % str(decipher))
		print ("---AES-CBC-MAC Test---")
		mac = SymCryptoUtil().CBCMAC(key, secret)
		print ("AES-CBC-MAC(len = %d): %s" % (len(mac), binascii.hexlify(mac)))
		if SymCryptoUtil().CBCMACVerify(key, secret, mac):
			print ("MAC verification succeeds.")
		else:
			print ("MAC verification fails.")
		print ("Random: %s" % SymCryptoUtil().GenerateRandom(16))

# test functions
if __name__ == '__main__':
	SymCryptoUtil().test()
	
