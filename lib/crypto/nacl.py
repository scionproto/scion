"""
nacl.py

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
import sys
import os

_FILE_PATH = ('./lib/crypto/python-tweetnacl-20140309/build/python' +
              sys.version[0:3] + '/tweetnacl.so')
if os.path.exists(_FILE_PATH):
    _LIB_PATH = ('./lib/crypto/python-tweetnacl-20140309/build/python' +
                 sys.version[0:3])
    sys.path.insert(0, _LIB_PATH)
    from tweetnacl import *
    from tweetnacl import _randreplace, _fromhex
else:
    print ('Shared library file does not exist in path ' + _FILE_PATH +
           '. Please run ./scion.sh init to build crypto library.')
