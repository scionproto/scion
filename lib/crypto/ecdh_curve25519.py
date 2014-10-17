"""
ecdh_curve25519.py

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

from ctypes import *
import platform, os, struct, base64

class ECDHCurve25519(object):
	"""
	ECDH Public Encryption Class
	
	"""
	
	def __init__(self):
		# load dynamic library
		self.curve_lib = None
		self.SecretKey = None
		if platform.machine() == 'x86_64':
			self.curve_lib = cdll.LoadLibrary("./curve25519-donna/curve25519-donna-c64.so")
		elif platform.machine() == 'i386':
			self.curve_lib = cdll.LoadLibrary("./curve25519-donna/curve25519-donna.so")
		if self.curve_lib != None:
			self.curve_lib.LinkTest()
			# basepoint[32] = {9};
			BasePointArray = bytearray(32)
			BasePointArray[0] = 9
			# convert to ctypes
			self.BasePoint =  create_string_buffer(struct.pack('32B', *BasePointArray), 32)
			del BasePointArray
		else:
			print ("Curve25519 Library is not linked..")
	
	def GenSecretKey(self):
		# random 32 bytes
		SecretKeyArray = bytearray(os.urandom(32))
		SecretKeyArray[0] &= 248
		SecretKeyArray[31] &= 127
		SecretKeyArray[31] |= 64
		self.SecretKey = create_string_buffer(struct.pack('32B', *SecretKeyArray), 32)
		del SecretKeyArray
		# print ("SecretKey(%d)= %s" % (sizeof(self.SecretKey), repr(self.SecretKey.raw)) )
	
	def ComputePublicKey(self):
		self.PubKey =  create_string_buffer(32)
		# curve25519(mypublic,mysecret,basepoint);
		self.curve_lib.curve25519_donna(self.PubKey, self.SecretKey, self.BasePoint)
		# print ("PubKey(%d)= %s" % (sizeof(self.PubKey), repr(self.PubKey.raw)) )
		return self.PubKey.value
	
	def EncodePublicKey(self):
		if self.PubKey != None:
			return base64.standard_b64encode(self.PubKey.value).decode('ascii').rstrip("=")
		else:
			return None
	
	def EncodePrivateKey(self):
		if self.SecretKey != None:
			return base64.standard_b64encode(self.SecretKey.value).decode('ascii').rstrip("=")
		else:
			return None
	
	def DecodePublicKey(self, rawbytes):
		if rawbytes != None:
			rawbytes += "="*((4 - len(rawbytes)%4)%4)
			self.PubKey = create_string_buffer(base64.b64decode(rawbytes), 32)
	
	def DecodePrivateKey(self, rawbytes):
		if rawbytes != None:
			rawbytes += "="*((4 - len(rawbytes)%4)%4)
			self.SecretKey = create_string_buffer(base64.b64decode(rawbytes), 32)
	
	def ComputeShareSecret(self, PubkeyRaw):
		# Compute shared secret, length = 32 bytes
		# curve25519(shared,mysecret,hispublic);
		sharedSecret =  create_string_buffer(32)
		self.curve_lib.curve25519_donna(sharedSecret, self.SecretKey, PubkeyRaw)
		return sharedSecret
	

# test functions
if __name__ == '__main__':
	
	print ("ECDH Curve25519 Test...")
	
	Alice_ECDH = ECDHCurve25519()
	Alice_ECDH.GenSecretKey()
	Alice_ECDH.ComputePublicKey()
	base64pub = Alice_ECDH.EncodePublicKey()
	base64pri = Alice_ECDH.EncodePrivateKey()
	print ("Alice's public key: %s" % base64pub)
	print ("Alice's private key: %s" % base64pri)
	
	Alice_ECDH_copy = ECDHCurve25519()
	Alice_ECDH_copy.DecodePublicKey(base64pub)
	Alice_ECDH_copy.DecodePrivateKey(base64pri)
	
	Bob_ECDH = ECDHCurve25519()
	Bob_ECDH.GenSecretKey()
	Bob_ECDH.ComputePublicKey()
	
	sharedSecret1 = Alice_ECDH.ComputeShareSecret(Bob_ECDH.PubKey)
	sharedSecret2 = Bob_ECDH.ComputeShareSecret(Alice_ECDH.PubKey)
	sharedSecret3 = Alice_ECDH_copy.ComputeShareSecret(Bob_ECDH.PubKey)
	
	print ("SharedSecret(%d)= %s" % (sizeof(sharedSecret1), repr(sharedSecret1.raw)) )
	print ("SharedSecret(%d)= %s" % (sizeof(sharedSecret2), repr(sharedSecret2.raw)) )
	print ("SharedSecret(%d)= %s" % (sizeof(sharedSecret3), repr(sharedSecret3.raw)) )