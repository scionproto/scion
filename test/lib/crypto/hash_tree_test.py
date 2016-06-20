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
<<<<<<< HEAD
    Unit tests for lib.crypto.hash_tree.ConnectedHashTree.verify
    """
    def test_1(self):
        if_ids = [23, 35, 120]
        seed = b"qwerty"
        hash_tree = ConnectedHashTree(if_ids, seed)
        # Check that the revocation proof is verifiable within the same T.
        root = hash_tree.get_root()
        proof = hash_tree.get_proof(35)  # if_id = 35.
=======
    Unit test for lib.crypto.hash_tree.ConnectedHashTree.verify
    """
    def test(self):
        if_ids = [23, 35, 120]
        seed = b"qwerty"
        inst = ConnectedHashTree(if_ids, seed)
        # Check that the revocation proof is verifiable within the same T.
        root = inst.get_root()
        proof = inst.get_proof(35)  # if_id = 35.
>>>>>>> bd089f05dfc0a9f58a359f4783214b1853d5f203
        self.assertTrue(ConnectedHashTree.verify(proof, root))


class TestConnectedHashTreeUpdate(SCIONCommonTest):
    """
<<<<<<< HEAD
    Unit tests for lib.crypto.hash_tree.ConnectedHashTree.update
    """
    def test_2(self):
        if_ids = [23, 35, 120]
        initial_seed = b"qwerty"
        hash_tree = ConnectedHashTree(if_ids, initial_seed)

        # Check that the revocation proof is verifiable across T and T+1.
        root = hash_tree.get_root()
        hash_tree.update(if_ids, b"new!!seed")
        proof = hash_tree.get_proof(35)  # if_id = 35.
        self.assertTrue(ConnectedHashTree.verify(proof, root))

        # Check that the revocation proof is "NOT" verifiable across T and T+2.
        root = hash_tree.get_root()
        hash_tree.update(if_ids, b"newseed.@1")
        hash_tree.update(if_ids, b"newseed/.@2")
        proof = hash_tree.get_proof(35)  # if_id = 35.
=======
    Unit test for lib.crypto.hash_tree.ConnectedHashTree.update
    """
    def test(self):
        if_ids = [23, 35, 120]
        initial_seed = b"qwerty"
        inst = ConnectedHashTree(if_ids, initial_seed)

        # Check that connected hash tree update works.
        root1_before_update = inst._ht1._nodes[0]
        root2_before_update = inst._ht2._nodes[0]
        inst.update(if_ids, b"new!!seed")
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
        if_ids = [23, 35, 120]
        initial_seed = b"qwerty"
        inst = ConnectedHashTree(if_ids, initial_seed)

        # Check that the revocation proof is verifiable across T and T+1.
        root = inst.get_root()
        inst.update(if_ids, b"new!!seed")
        proof = inst.get_proof(35)  # if_id = 35.
        self.assertTrue(ConnectedHashTree.verify(proof, root))

    def test_two_timesteps(self):
        if_ids = [23, 35, 120]
        initial_seed = b"qwerty"
        inst = ConnectedHashTree(if_ids, initial_seed)

        # Check that the revocation proof is "NOT" verifiable across T and T+2.
        root = inst.get_root()
        inst.update(if_ids, b"newseed.@1")
        inst.update(if_ids, b"newseed/.@2")
        proof = inst.get_proof(35)  # if_id = 35.
>>>>>>> bd089f05dfc0a9f58a359f4783214b1853d5f203
        self.assertFalse(ConnectedHashTree.verify(proof, root))

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
