import sys,os
from distutils.util import get_platform

# test library file existence
file_path = 'python-tweetnacl-20140309/build/python'+sys.version[0:3]+'/tweetnacl.so'
if os.path.exists(file_path):
	libpath = 'python-tweetnacl-20140309/build/python'+sys.version[0:3]
	sys.path.insert(0, libpath)
	from tweetnacl import *
	from tweetnacl import _randreplace, _fromhex
else:
	print ("Shared library file does not exist. Please run ./scion.sh setup to build crypto librry.")


