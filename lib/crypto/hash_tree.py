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
:mod:`hash_tree` --- SCION time-connected hash-tree implementation
==================================================================
"""
# External
from Crypto.Hash import SHA256

# SCION
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.util import Raw

class HashTree(object):
    """
    Class encapsulating a scion hash-tree.

    The number of interfaces and epoch times are configurable. 
    The used hash function needs to implement the hashlib interface.

    """

    def __init__(self, if_ids, n_epochs, seed, hash_func):
        self._seed = seed
        self._hash_func = hash_func

        # Calculate the depth of the smallest complete binary tree that can
        # have (num(if_id) * num(epoch)) leaves.
        self._depth = 0
        least_higher_2_power = 1
        length = len(if_ids) * n_epochs

        temp = length
        while (temp > 0):
            temp = temp // 2
            self._depth = self._depth + 1
            least_higher_2_power = least_higher_2_power * 2

        if (least_higher_2_power == length * 2):
            least_higher_2_power = length
            self._depth = self._depth - 1

        # Create a (heap-like) array to represent the complete binary tree.
        self._nodes = []
        node_count = least_higher_2_power * 2 - 1
        for i in range(node_count):
            self._nodes.append("")

        # Compute and fill in the hash values for the leaves (left to right).
        self._leaves_start_idx = least_higher_2_power - 1
        idx = self._leaves_start_idx
        self._if2idx = {}
        for if_id in if_ids:         # For given (if_id, epoch) leaves
            self._if2idx[if_id] = idx
            for i in range(n_epochs):
                raw_nonce = (str(seed) +str(if_id) + str(i)).encode('utf-8')
                nonce = self._hash_func.new(raw_nonce).digest()
                if_tuple = (str(if_id) + str(i) + str(nonce)).encode('utf-8')
                self._nodes[idx] = self._hash_func.new(if_tuple).digest()
                idx = idx + 1

        while (idx < node_count):  # For extra leaves added to complete tree
            self._nodes[idx] = self._hash_func.new(b"0").digest()
            idx = idx + 1

        # Compute and fill in the hash values for internal nodes (bottom up).
        for idx in reversed(range(self._leaves_start_idx)):
            hash_concat = self._nodes[idx * 2 + 1] + self._nodes[idx * 2 + 2]
            self._nodes[idx] = self._hash_func.new(hash_concat).digest()

    def get_proof(self, if_id, epoch, prev_root, next_root):
        assert if_id in self._if2idx.keys(), "if_id not found in AS"

        # Obtain the nonce for the (if_id, epoch) pair using the seed.
        raw_nonce = (str(self._seed) + str(if_id) + str(epoch)).encode('utf-8')
        nonce = self._hash_func.new(raw_nonce).digest()

        # Obtain the sibling hashes along with their left/right position info.
        siblings = []
        idx = self._if2idx[if_id] + epoch
        while (idx > 0):
            if (idx % 2 == 0):
                siblings.append((True, self._nodes[idx - 1]))
            else:
                siblings.append((False, self._nodes[idx + 1]))
            idx = (idx - 1) // 2

        # Using the above fields, construct a RevInfo capnp as the proof.
        return RevocationInfo.from_values(if_id,
                                          epoch,
                                          nonce, 
                                          siblings, 
                                          prev_root, 
                                          next_root)

class ConnectedHashTree(object):
    """
    Class encapsulating a scion time-connected hash-tree.

    The number of interfaces and epoch times are configurable. 
    The used hash function needs to implement the hashlib interface.

    """

    def __init__(self, if_ids, n_epochs, seeds, hash_func=SHA256):
        assert len(if_ids)*n_epochs >= 1, "Hash tree must have at least 1 leaf"
        assert len(seeds) == 3, "Not provided 3 seeds for the Hash tree"
        self._hash_func = hash_func
        self._ht0_root = hash_func.new(str(seeds[0]).encode('utf-8')).digest()
        self._ht1 = HashTree(if_ids, n_epochs, seeds[1], hash_func)
        self._ht2 = HashTree(if_ids, n_epochs, seeds[2], hash_func)

    def update(self, if_ids, n_epochs, seed):
        self._ht0_root = self._ht1._nodes[0]
        self._ht1 = self._ht2
        self._ht2 = HashTree(if_ids, n_epochs, seed, self._hash_func)

    def get_root(self):
        root1 = self._ht1._nodes[0]
        root2 = self._ht2._nodes[0]
        root12 = self._hash_func.new(root1 + root2).digest()
        return root12

    def get_proof(self, if_id, epoch):
        # Call get_proof on the hashtree at T, passing roots for T-1 and T+1.
        return self._ht1.get_proof(if_id,
                                   epoch,
                                   self._ht0_root,
                                   self._ht2._nodes[0])

    @staticmethod
    def get_possible_hashes(proof, hash_func=SHA256):
        # Calculate the hashes upwards till the tree root.
        if_tuple = (str(proof.ifID) + str(proof.epoch) + str(proof.nonce)) \
                   .encode('utf-8')
        curr_hash = hash_func.new(if_tuple).digest()

        for i in range(len(proof.siblings)):
            is_left = proof.siblings[i].isLeft
            sibling_hash = proof.siblings[i].hash
            if is_left:
                curr_hash = sibling_hash + curr_hash
            else:
                curr_hash = curr_hash + sibling_hash
            curr_hash = hash_func.new(curr_hash).digest()

        # Get the hashes for the tree joins T-1:T and T:T+1 and return them.
        hash01 = hash_func.new(proof.prevRoot + curr_hash).digest()
        hash12 = hash_func.new(curr_hash + proof.nextRoot).digest() 
        return (hash01, hash12)

    @staticmethod
    def verify(revProof, root, curr_epoch, hash_func=SHA256):
        proof = revProof.p
        assert not isinstance(proof, bytes)
        # Check if the current epoch matches the epoch in the proof.
        if (proof.epoch != curr_epoch):
            return False
        # Check that either hash of T-1:T or T:T+1 matches the root.
        hash01,hash12 = ConnectedHashTree.get_possible_hashes(proof, hash_func)
        return (hash01 == root) or (hash12 == root)