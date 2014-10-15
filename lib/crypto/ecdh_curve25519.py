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

from ctypes import cdll
import platform

class ECDHCurve25519(object):
	"""
	ECDH Public Encryption Class
	
	"""
	
	def __init__(self):
		# load dynamic library
		curve_lib = None
		if platform.machine() == 'x86_64':
			curve_lib = cdll.LoadLibrary("./curve25519-donna/curve25519-donna-c64.so")
		elif platform.machine() == 'i386':
			curve_lib = cdll.LoadLibrary("./curve25519-donna/curve25519-donna.so")
		if curve_lib != None:
			curve_lib.LinkTest()
		else:
			print ("Curve25519 Library is not linked..")
		
	def test(self):
		print ("ECDHCurve25519 Test..")

# test functions
if __name__ == '__main__':
	ECDHCurve25519().test()
	
