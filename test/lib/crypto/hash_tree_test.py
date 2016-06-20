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


class TestConnectedHashtreeVerify(SCIONCommonTest):
    """
    Unit test for lib.crypto.hash_tree.ConnectedHashTree.verify
    """
    def test(self):
        # Check that the revocation proof is verifiable within the same T.
        # Setup
        if_ids = [23, 35, 120]
        seed = b"qwerty"
        inst = ConnectedHashTree(if_ids, seed)
        root = inst.get_root()
        proof = inst.get_proof(35)  # if_id = 35.
        # Call and tests
        self.assertTrue(ConnectedHashTree.verify(proof, root))


class TestConnectedHashTreeUpdate(SCIONCommonTest):
    """
    Unit test for lib.crypto.hash_tree.ConnectedHashTree.update
    """
    def test(self):
        # Check that connected hash tree update works.
        # Setup
        if_ids = [23, 35, 120]
        initial_seed = b"qwerty"
        inst = ConnectedHashTree(if_ids, initial_seed)
        root1_before_update = inst._ht1._nodes[0]
        root2_before_update = inst._ht2._nodes[0]
        # Call
        inst.update(if_ids, b"new!!seed")
        # Tests
        root0_after_update = inst._ht0_root
        root1_after_update = inst._ht1._nodes[0]
        self.assertTrue(
            (root1_before_update == root0_after_update) and
            (root2_before_update == root1_after_update))


class TestConnectedHashTreeUpdateAndVerify(SCIONCommonTest):
    """
    Unit tests for lib.crypto.hash_tree.ConnectedHashTree.verify
    used along with lib.crypto.hash_tree.ConnectedHashTree.update
    """
    def test_one_timestep(self):
        # Check that the revocation proof is verifiable across T and T+1.
        # Setup
        if_ids = [23, 35, 120]
        initial_seed = b"qwerty"
        inst = ConnectedHashTree(if_ids, initial_seed)
        root = inst.get_root()
        # Call
        inst.update(if_ids, b"new!!seed")
        # Tests
        proof = inst.get_proof(35)  # if_id = 35.
        self.assertTrue(ConnectedHashTree.verify(proof, root))

    def test_two_timesteps(self):
        # Check that the revocation proof is "NOT" verifiable across T and T+2.
        # Setup
        if_ids = [23, 35, 120]
        initial_seed = b"qwerty"
        inst = ConnectedHashTree(if_ids, initial_seed)
        root = inst.get_root()
        # Call
        inst.update(if_ids, b"newseed.@1")
        inst.update(if_ids, b"newseed/.@2")
        # Tests
        proof = inst.get_proof(35)  # if_id = 35.
        self.assertFalse(ConnectedHashTree.verify(proof, root))

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
