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
:mod:`lib_crypto_hash_tree_test` --- lib.crypto.hash_tree unit tests
======================================================================
"""
# Stdlib
import logging
import unittest

# SCION
from lib.crypto.hash_tree import ConnectedHashTree
from test.testcommon import SCIONCommonTest


class TestHashTree(SCIONCommonTest):
    """
    Unit tests for hash_tree.py.
    """
    def test_hash_tree(self):
        """
        Test the connected hash tree APIs.
        """
        if_ids = [23, 35, 120]
        n_epochs = 5
        initial_seeds = ["asdf", "qwerty", "zx"]
        hash_tree = ConnectedHashTree(if_ids, n_epochs, initial_seeds)
        # Default hash_func for class hash tree & verify() function is SHA256.

        # Check that the revocation proof is verifiable within the same T.
        root = hash_tree.get_root()
        proof = hash_tree.get_proof(35, 3)  # if_id = 35, epoch = 3.
        self.assertTrue(ConnectedHashTree.verify(proof, root, 3))

        # Check that the revocation proof is verifiable across T and T+1.
        root = hash_tree.get_root()
        hash_tree.update(if_ids, n_epochs, "new!!seed")
        proof = hash_tree.get_proof(35, 3)  # if_id = 35, epoch = 3.
        self.assertTrue(ConnectedHashTree.verify(proof, root, 3))

        # Check that the revocation proof is "NOT" verifiable across T and T+2.
        root = hash_tree.get_root()
        hash_tree.update(if_ids, n_epochs, "newseed.@1")
        hash_tree.update(if_ids, n_epochs, "newseed/.@2")
        proof = hash_tree.get_proof(35, 3)  # if_id = 35, epoch = 3.
        self.assertFalse(ConnectedHashTree.verify(proof, root, 3))

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
