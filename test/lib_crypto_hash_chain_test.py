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
:mod:`lib_crypto_hash_chain_test` --- lib.crypto.hash_chain unit tests
======================================================================
"""
# Stdlib
import logging
import unittest

# External packages
from Crypto import Random
import nose.tools as ntools

# SCION
from lib.crypto.hash_chain import HashChain, HashChainExhausted
from test.testcommon import SCIONCommonTest


class TestHashChain(SCIONCommonTest):
    """
    Unit tests for hash_chain.py.
    """
    def test_hash_chain(self):
        """
        Test the hash chain APIs.
        """
        N = 20
        hc = HashChain(Random.new().read(32), N)
        target = hc.current_element()
        self.assertTrue(target is not None)
        for _ in range(N - 2):
            self.assertTrue(HashChain.verify(hc.next_element(), target))
            hc.move_to_next_element()
        ntools.assert_raises(HashChainExhausted, hc.move_to_next_element)
        self.assertFalse(HashChain.verify(Random.new().read(32), target))

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
