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
# Stdlib
import struct

# External
from Crypto.Hash import SHA256

# SCION
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

        # Calculate the depth of the smallest complete binary tree having the
        # (if_id , epoch) pairs as leaves.
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

    def get_proof(self, if_id, epoch):
        assert if_id in self._if2idx.keys(), "if_id not found in AS"
        packed = []

        # Pack the if_id, ti (epoch) and nonce of the leaf into the proof.
        packed.append(struct.pack("!HH", if_id, epoch))
        raw_nonce = (str(self._seed) + str(if_id) + str(epoch)).encode('utf-8')
        nonce = self._hash_func.new(raw_nonce).digest()
        packed.append(struct.pack("!32s", nonce))

        # Pack the sibling count and their hash values (along with l/r).
        packed.append(struct.pack("!B", self._depth))
        idx = self._if2idx[if_id] + epoch
        while (idx > 0):
            if (idx % 2 == 0):
                packed.append(struct.pack("!33s", b"l" + self._nodes[idx - 1]))
            else:
                packed.append(struct.pack("!33s", b"r" + self._nodes[idx + 1]))
            idx = (idx - 1) // 2
        return packed

    def print_tree(self):
        for s in self._nodes:
            print(s)

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
        packed = self._ht1.get_proof(if_id, epoch)
        packed.append(struct.pack("!32s", self._ht0_root))
        packed.append(struct.pack("!32s", self._ht2._nodes[0]))
        raw = b"".join(packed)
        padding = 8 - len(raw)%8
        if padding==8:
            padding=0
        packed.append(bytes(padding))
        raw = b"".join(packed)

        return raw

    @staticmethod
    def _parse(raw):
        assert len(raw)%8==0, "Proof not multiple of 8 bytes"
        padding = 8-len(raw)%8
        if padding==8:
            padding=0

        data = Raw(raw, "RevocationProof", len(raw))
        # Unpack all the fields of the revocation proof.
        if_id, epoch = struct.unpack("!HH", data.pop(4))
        nonce = struct.unpack("!32s", data.pop(32))[0]
        num_siblings = data.pop(1)
        siblings = []
        for i in range(num_siblings):
            siblings.append(chr(data.pop(1)))
            siblings.append(struct.unpack("!32s", data.pop(32))[0])
        root0 = struct.unpack("!32s", data.pop(32))[0]
        root2 = struct.unpack("!32s", data.pop(32))[0]
        data.pop(padding)
        # Pack the extracted fields into a tuple and return
        return (if_id, epoch, nonce, num_siblings, siblings, root0, root2)

    @staticmethod
    def get_possible_hashes(raw_proof, hash_func=SHA256):
        # Extract fields from the raw proof.
        if_id, epoch, nonce, num_siblings, siblings, root0, root2 = \
            ConnectedHashTree._parse(raw_proof)
        
        # Calculate the hashes upwards till the tree root.
        if_tuple = (str(if_id) + str(epoch) + str(nonce)).encode('utf-8')
        curr_hash = hash_func.new(if_tuple).digest()
        for i in range(num_siblings):
            new_hash = siblings[2 * i + 1]
            if (siblings[2 * i] == 'l'):
                raw_hash = new_hash + curr_hash
            else:
                raw_hash = curr_hash + new_hash
            curr_hash = hash_func.new(raw_hash).digest()

        # Get the hashes for both the subtrees T-1:T and T:T+1.
        hash01 = hash_func.new(root0 + curr_hash).digest()
        hash12 = hash_func.new(curr_hash + root2).digest() 
        """
        # Printing fields of the proof
        print("IF_ID: ", if_id)
        print("Epoch: ", epoch)
        print("#siblings: ", num_siblings)
        print("Siblings: ")
        for i in range(num_siblings):
            print(siblings[2 * i], siblings[2 * i + 1])
        print("Rt-1: ", root0)
        print("Rt+1: ", root2)

        # Printing computed roots of the connected hash tree.
        print("\nHash01: ", hash01)
        print("\nHash12: ", hash12)
        """
        return (hash01, hash12)

    @staticmethod
    def verify(raw_proof, root, curr_epoch, hash_func=SHA256):
        # Check if the current epoch matches the epoch in the proof.
        data = Raw(raw_proof, "RevocationProof")
        if_id, epoch = struct.unpack("!HH", data.pop(4))
        if (epoch != curr_epoch):
            return False

        # Check that either hash of T-1:T or T:T+1 matches the root.
        hash01, hash12 = ConnectedHashTree.get_possible_hashes(raw_proof, \
                                                               hash_func)
        return (hash01 == root) or (hash12 == root)