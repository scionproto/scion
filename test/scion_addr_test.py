# Copyright 2015 ETH Zurich
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
:mod:`scion_addr_test` --- SCION extension header tests
=====================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.scion_addr import SCIONAddr

class TestSCIONAddrInit(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.__init__
    """
    def test_basic(self):
    	scion_addr = SCIONAddr()
    	ntools.eq_(scion_addr.isd_id, None)
    	ntools.eq_(scion_addr.ad_id, None)
    	ntools.eq_(scion_addr.host_addr, None)
    	ntools.eq_(scion_addr.addr_len, 0)

    @patch("lib.packet.scion_addr.SCIONAddr.parse")
    def test_raw(self, parse):
        scion_addr = SCIONAddr("data")
        parse.assert_called_once_with("data")

if __name__ == "__main__":
    nose.run(defaultTest=__name__)