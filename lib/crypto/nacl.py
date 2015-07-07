# Copyright 2014 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`nacl` --- NaCl library loader
===================================
"""
# Stdlib
import sys
import os

_THIS_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
_LIB_DIR = os.path.join(
    _THIS_FILE_DIR,
    'python-tweetnacl-20140309/build/python{}'.format(sys.version[0:3])
)
_LIB_FILE_PATH = os.path.join(_LIB_DIR, 'tweetnacl.so')

if os.path.exists(_LIB_FILE_PATH):
    sys.path.insert(0, _LIB_DIR)
    from tweetnacl import *   # noqa
    from tweetnacl import _randreplace, _fromhex   # noqa
else:
    print('Shared library file does not exist in path ' + _LIB_FILE_PATH +
          '. Please run ./scion.sh init to build crypto library.')
