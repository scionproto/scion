"""
hash_chain_test.py

Copyright 2015 ETH Zurich

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
from lib.crypto.hash_chain import HashChain
import logging
import unittest

from Crypto import Random


class TestHashChain(unittest.TestCase):
    """
    Unit tests for hash_chain.py.
    """
    def test_hash_chain(self):
        N = 20
        hc = HashChain(Random.new().read(32), N)

        target = hc.next_element()
        self.assertTrue(target == hc.current_element())

        for _ in range(N - 1):
            self.assertTrue(HashChain.verify(hc.next_element(), target))

        self.assertFalse(HashChain.verify(Random.new().read(32), target))

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
