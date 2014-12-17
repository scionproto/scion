import sys,os
from distutils.util import get_platform

# test library file existence
file_path = ('../lib/crypto/python-tweetnacl-20140309/build/python' +
	sys.version[0:3] + '/tweetnacl.so')
if os.path.exists(file_path):
	libpath = ('../lib/crypto/python-tweetnacl-20140309/build/python' +
		sys.version[0:3])
	sys.path.insert(0, libpath)
	from tweetnacl import *
	from tweetnacl import _randreplace, _fromhex
else:
	print ("Shared library file does not exist in path " + file_path +
		". Please run ./scion.sh init to build crypto library.")


