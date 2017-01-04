# Copyright 2016 ETH Zurich
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
import time

# External
from Crypto.Hash import SHA256

# SCION
from lib.defines import (
    HASHTREE_EPOCH_TIME,
    HASHTREE_EPOCH_TOLERANCE,
    HASHTREE_N_EPOCHS,
    HASHTREE_TTL,
)
from lib.packet.path_mgmt.rev_info import RevocationInfo


class HashTree(object):
    """
    Class encapsulating a scion hash-tree.
    The number of interfaces and epoch times are configurable.
    The used hash function needs to implement the hashlib interface.
    """

    def __init__(self, isd_as, if_ids, seed, hash_func=SHA256):
        """
        :param ISD_AS isd_as: The ISD_AS of the AS.
        :param List[int] if_ids: List of interface IDs of the AS.
        :param str seed: Seed for creating hash-tree nonces.
        :param hash_func: Hash function that implements hashlib interface.
        """
        self._isd_as = isd_as
        self._seed = seed
        self._n_epochs = HASHTREE_N_EPOCHS
        self._hash_func = hash_func
        self._setup(if_ids)

    def _setup(self, if_ids):
        self.calc_tree_depth(len(if_ids) * self._n_epochs)
        self.create_tree(if_ids)

    def calc_tree_depth(self, leaf_count):
        """
        Calculate the depth of the smallest complete binary tree that can
        have at least 'leaf_count' leaves.

        :param int leaf_count: Count of leaves the tree should at least have.
        """
        self._depth = 0
        least_higher_2_power = 1
        temp = leaf_count
        while temp > 0:
            temp = temp // 2
            self._depth = self._depth + 1
            least_higher_2_power = least_higher_2_power * 2
        # If leaf count is a power of 2, then reduce the calculated depth by 1.
        if least_higher_2_power == leaf_count * 2:
            least_higher_2_power = leaf_count
            self._depth -= 1

    def create_tree(self, if_ids):
        """
        Create a (heap-like) array of nodes to represent the hash-tree.

        :param List[int] if_ids: list of interface IDs of the AS.
        """
        self._nodes = []
        node_count = pow(2, self._depth + 1) - 1
        for i in range(node_count):
            self._nodes.append("")

        # Compute and fill in the hash values for the leaves (left to right).
        self._leaves_start_idx = pow(2, self._depth) - 1
        idx = self._leaves_start_idx
        self._if2idx = {}
        for if_id in if_ids:  # For given (if_id, epoch) leaves
            self._if2idx[if_id] = idx
            for i in range(self._n_epochs):
                raw_nonce = (self._seed + struct.pack("!qq", if_id, i))
                nonce = self._hash_func.new(raw_nonce).digest()
                if_tuple = struct.pack("!qq", if_id, i) + nonce
                self._nodes[idx] = self._hash_func.new(if_tuple).digest()
                idx = idx + 1
        while idx < node_count:  # For extra leaves added to complete tree
            self._nodes[idx] = self._hash_func.new(b"0").digest()
            idx = idx + 1

        # Compute and fill in the hash values for internal nodes (bottom up).
        for idx in reversed(range(self._leaves_start_idx)):
            hash_concat = self._nodes[idx * 2 + 1] + self._nodes[idx * 2 + 2]
            self._nodes[idx] = self._hash_func.new(hash_concat).digest()

    def get_proof(self, if_id, epoch, prev_root, next_root):
        """
        Obtain the proof for revoking a given interface at a given epoch.

        :param int if_id: ID of the interface to be revoked.
        :param int epoch: epoch for which the interface is to be revoked.
        :param bytes prev_root: hash of the previous root.
        :param bytes next_root: hash of the next root.
        """
        assert if_id in self._if2idx.keys(), "if_id not found in AS"
        # Obtain the nonce for the (if_id, epoch) pair using the seed.
        raw_nonce = self._seed + struct.pack("!qq", if_id, epoch)
        nonce = self._hash_func.new(raw_nonce).digest()

        # Obtain the sibling hashes along with their left/right position info.
        siblings = []
        idx = self._if2idx[if_id] + epoch
        while idx > 0:
            if idx % 2 == 0:
                siblings.append((True, self._nodes[idx - 1]))
            else:
                siblings.append((False, self._nodes[idx + 1]))
            idx = (idx - 1) // 2

        # Using the above fields, construct a RevInfo capnp as the proof.
        return RevocationInfo.from_values(
            self._isd_as, if_id, epoch, nonce, siblings, prev_root, next_root)


class ConnectedHashTree(object):
    """
    Class encapsulating a scion time-connected hash-tree.

    The number of interfaces and epoch times are configurable.
    The used hash function needs to implement the hashlib interface.

    """

    def __init__(self, isd_as, if_ids, seed,
                 hash_func=SHA256):  # pragma: no cover
        """
        :param ISD_AS isd_as: The ISD_AS of the AS.
        :param List[int] if_ids: list of interface IDs of the AS.
        :param List[str] seeds: list of 3 seeds for creating hash-tree nonces.
        :param hash_func: hash function that implements hashlib interface.
        """
        assert len(if_ids)*HASHTREE_N_EPOCHS >= 1, "Must have at least 1 leaf"
        ttl_window = self.get_ttl_window()
        seed1 = seed + (ttl_window - 1).to_bytes(8, 'big')
        seed2 = seed + (ttl_window + 0).to_bytes(8, 'big')
        seed3 = seed + (ttl_window + 1).to_bytes(8, 'big')

        self._hash_func = hash_func
        self._ht0_root = hash_func.new(str(seed1).encode('utf-8')).digest()
        self._ht1 = HashTree(isd_as, if_ids, seed2, hash_func)
        self._ht2 = HashTree(isd_as, if_ids, seed3, hash_func)

    @classmethod
    def get_ttl_window(cls):
        cur_time = int(time.time())
        return cur_time // HASHTREE_TTL

    @classmethod
    def get_current_epoch(cls):
        cur_window = int(time.time()) % HASHTREE_TTL
        return cur_window // HASHTREE_EPOCH_TIME

    @classmethod
    def get_time_since_epoch(cls):
        return time.time() % HASHTREE_EPOCH_TIME

    @classmethod
    def get_time_since_ttl(cls):
        return time.time() % HASHTREE_TTL

    @classmethod
    def get_time_till_next_ttl(cls):
        return HASHTREE_TTL - cls.get_time_since_ttl()

    @classmethod
    def get_next_tree(cls, isd_as, if_ids, seed, hash_func=SHA256):
        seed += (cls.get_ttl_window() + 2).to_bytes(8, 'big')
        return HashTree(isd_as, if_ids, seed, hash_func)

    def update(self, next_tree):
        self._ht0_root = self._ht1._nodes[0]
        self._ht1 = self._ht2
        self._ht2 = next_tree

    def get_root(self):
        """
        Obtain the root of the connected hash-tree across trees for T and T+1.
        """
        root1 = self._ht1._nodes[0]
        root2 = self._ht2._nodes[0]
        root12 = self._hash_func.new(root1 + root2).digest()
        return root12

    def get_proof(self, if_id):
        # Call get_proof on the hashtree at T, passing roots for T-1 and T+1.
        epoch = ConnectedHashTree.get_current_epoch()
        return self._ht1.get_proof(
            if_id, epoch, self._ht0_root, self._ht2._nodes[0])

    @classmethod
    def get_possible_hashes(cls, revProof, hash_func=SHA256):
        """
        Compute the hashes of the connected hash-tree roots given revProof.
        """
        # Calculate the hashes upwards till the tree root (of T).
        proof = revProof.p
        if_tuple = struct.pack("!qq", proof.ifID, proof.epoch) + proof.nonce
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

    @classmethod
    def verify(cls, revProof, root, hash_func=SHA256):  # pragma: no cover
        """
        Verify whether revProof proves the revocation for the current epoch,
        given the root of the connected hash-tree.

        :param RevInfo revProof: proof for the revocation.
        :param bytes root: hash of the root, used for validating the proof.
        :param hash_func: hash function that implements hashlib interface.
        """
        assert not isinstance(revProof.p, bytes)
        h01, h12 = cls.get_possible_hashes(revProof, hash_func)
        return h01 == root or h12 == root

    @classmethod
    def verify_epoch(cls, epoch):
        cur_epoch = cls.get_current_epoch()
        gap_time = cls.get_time_since_epoch()
        return (epoch == cur_epoch or
                cur_epoch == epoch + 1 and gap_time < HASHTREE_EPOCH_TOLERANCE)
