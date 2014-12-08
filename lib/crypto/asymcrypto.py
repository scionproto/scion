"""
AsymCrypto.py

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

from tweetnacl import *
from ctypes import *
import platform, random, string, struct, base64

class AsymCrypto(object):
	"""
	Asymmetric Cryptography Class
	"""
	
	def __init__(self):
		# initialization
		self.SigPk = None
		self.SigSk = None
		self.Pk = None
		self.Sk = None
	
	def SignatureKeyGen(self):
		# Ed25519 Signature
		(self.SigPk, self.SigSk) = crypto_sign_ed25519_keypair() 
		
	def EncryptionKeyGen(self):
		# curve25519-xsalsa20-poly1305
		(self.Pk, self.Sk) = crypto_box_curve25519xsalsa20poly1305_keypair() 
	
	def SignaturePubKey(self):	
		if self.SigPk != None:
			return base64.standard_b64encode(self.SigPk).decode('ascii').rstrip("=")
		else:
			raise Exception("Error: public-key for Ed25519 is NULL.")
	
	def SignaturePriKey(self):	
		if self.SigSk != None:
			return base64.standard_b64encode(self.SigSk).decode('ascii').rstrip("=")
		else:
			raise Exception("Error: private-key for Ed25519 is NULL.")
	
	def EncryptionPubKey(self):	
		if self.Pk != None:
			return base64.standard_b64encode(self.Pk).decode('ascii').rstrip("=")
		else:
			raise Exception("Error: public-key for Encryption is NULL.")
	
	def EncryptionPriKey(self):	
		if self.Sk != None:
			return base64.standard_b64encode(self.Sk).decode('ascii').rstrip("=")
		else:
			raise Exception("Error: private-key for Encryption is NULL.")
	
	def LoadSignaturePubKey(self, rawbytes):
		if rawbytes != None:
			rawbytes += "="*((4 - len(rawbytes)%4)%4)
			self.SigPk = create_string_buffer(base64.b64decode(rawbytes), crypto_sign_ed25519_PUBLICKEYBYTES)
	
	def LoadSignaturePriKey(self, rawbytes):
		if rawbytes != None:
			rawbytes += "="*((4 - len(rawbytes)%4)%4)
			self.SigSk = create_string_buffer(base64.b64decode(rawbytes), crypto_sign_ed25519_SECRETKEYBYTES)
	
	def LoadEncryptionPubKey(self, rawbytes):
		if rawbytes != None:
			rawbytes += "="*((4 - len(rawbytes)%4)%4)
			self.Pk = create_string_buffer(base64.b64decode(rawbytes), crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES)
	
	def LoadEncryptionPriKey(self, rawbytes):
		if rawbytes != None:
			rawbytes += "="*((4 - len(rawbytes)%4)%4)
			self.Sk = create_string_buffer(base64.b64decode(rawbytes), crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES)
	
	def ENCipher(self, data, rawbytes_pubkey):
		rawbytes_pubkey += "="*((4 - len(rawbytes_pubkey)%4)%4)
		pubkey = create_string_buffer(base64.b64decode(rawbytes_pubkey), crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES)
		if pubkey == None:
			raise Exception("Error: recipient_pubkey is NULL.")
			return
		if data == None:
			raise Exception("Error: signed data is NULL.")
			return
		nonce = randombytes(24)
		cipher = crypto_box_curve25519xsalsa20poly1305(data, nonce, pubkey, self.Sk)
		return nonce+cipher
	
	def DECipher(self, data, rawbytes_pubkey):
		rawbytes_pubkey += "="*((4 - len(rawbytes_pubkey)%4)%4)
		pubkey = create_string_buffer(base64.b64decode(rawbytes_pubkey), crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES)
		if pubkey == None:
			raise Exception("Error: recipient_pubkey is NULL.")
			return
		if data == None:
			raise Exception("Error: cipher is NULL.")
			return
		nonce = data[:24]
		cipher = data[24:]
		return crypto_box_curve25519xsalsa20poly1305_open(cipher, nonce, pubkey, self.Sk)
	
	def GenSignature(self, data):
		if data != None:
			return crypto_sign_ed25519(data, self.SigSk)
		else:
			raise Exception("Error: signed data is NULL.")
	
	def VerifySignature(self, sig):
		if sig != None:
			return crypto_sign_ed25519_open(sig, self.SigPk)
		else:
			raise Exception("Error: signature data is NULL.")
	

# test functions
if __name__ == '__main__':
	
	print ("Asymmetric Crypto Engine Test...")
	
	Alice_Key = AsymCrypto()
	Alice_Key.SignatureKeyGen()
	Alice_Key.EncryptionKeyGen()
	alice_pub1 = Alice_Key.SignaturePubKey()
	alice_pri1 = Alice_Key.SignaturePriKey()
	alice_pub2 = Alice_Key.EncryptionPubKey()
	alice_pri2 = Alice_Key.EncryptionPriKey()
	print ("Alice's public key (ed25519): %s" % alice_pub1)
	print ("Alice's private key (ed25519): %s" % alice_pri1)
	print ("Alice's public key (curve25519xsalsa20poly1305): %s" % alice_pub2)
	print ("Alice's private key (curve25519xsalsa20poly1305): %s" % alice_pri2)
	
	print ("Ed25519 Signature Test...")
	for x in range(0, 10):
		msg = ''.join(random.choice(string.lowercase) for i in range(20))
		print ("random message :", msg)
		msg_sig = Alice_Key.GenSignature(msg)
		print ("Signature attached to message:", msg_sig)
		msg_verified = Alice_Key.VerifySignature(msg_sig)
		print ("Verified message:", msg_verified)
		print ("\n")
		
	
	Bob_Key = AsymCrypto()
	Bob_Key.SignatureKeyGen()
	Bob_Key.EncryptionKeyGen()
	bob_pub = Bob_Key.EncryptionPubKey()
	
	print ("curve25519xsalsa20poly1305 Publie-Key Encryption Test...")
	msg = ''.join(random.choice(string.lowercase) for i in range(20))
	print ("encrypted message :", msg)
	
	for x in range(0, 10):
		cipher = Bob_Key.ENCipher(msg, alice_pub2)
		print ("cipher:", cipher)
		original = Alice_Key.DECipher(cipher, bob_pub)
		print ("deCipher:", original)
		print ("\n")