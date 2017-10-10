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

# SCION
from lib.crypto.symcrypto import hash_func_for_type
from lib.defines import (
    HASHTREE_EPOCH_TIME,
    HASHTREE_EPOCH_TOLERANCE,
)
from lib.packet.path_mgmt.rev_info import RevocationInfo


class HashTree(object):
    """
    Class encapsulating a scion hash-tree.
    The number of interfaces and epoch times are configurable.
    The used hash function needs to implement the hashlib interface.
    """

    def __init__(self, isd_as, if_ids, seed, ttl, hash_type):
        """
        :param ISD_AS isd_as: The ISD_AS of the AS.
        :param List[int] if_ids: List of interface IDs of the AS.
        :param str seed: Seed for creating hash-tree nonces.
        :param int ttl: The TTL window for which this hash tree is valid (in seconds).
        :param hash_type: Hash function type.
        """
        assert ttl % HASHTREE_EPOCH_TIME == 0,\
            "HashTree TTL must be a multiple of %ds" % HASHTREE_EPOCH_TIME
        self._isd_as = isd_as
        self._seed = seed
        self._ttl = ttl
        self._hash_type = hash_type
        self._hash_func = hash_func_for_type(hash_type)
        self._n_epochs = ttl // HASHTREE_EPOCH_TIME
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
                nonce = self._hash_func(raw_nonce)
                if_tuple = struct.pack("!qq", if_id, i) + nonce
                self._nodes[idx] = self._hash_func(if_tuple)
                idx = idx + 1
        null_hash = self._hash_func(b"0")
        while idx < node_count:  # For extra leaves added to complete tree
            self._nodes[idx] = null_hash
            idx = idx + 1

        # Compute and fill in the hash values for internal nodes (bottom up).
        for idx in reversed(range(self._leaves_start_idx)):
            hash_concat = self._nodes[idx * 2 + 1] + self._nodes[idx * 2 + 2]
            self._nodes[idx] = self._hash_func(hash_concat)

    def get_proof(self, if_id, epoch, prev_root, next_root):
        """
        Obtain the proof for revoking a given interface at a given epoch.

        :param int if_id: ID of the interface to be revoked.
        :param int epoch: epoch for which the interface is to be revoked.
        :param bytes prev_root: hash of the previous root.
        :param bytes next_root: hash of the next root.
        """
        assert if_id in self._if2idx.keys(), "if_id not found in AS"
        relative_epoch = epoch % self._n_epochs
        # Obtain the nonce for the (if_id, epoch) pair using the seed.
        raw_nonce = self._seed + struct.pack("!qq", if_id, relative_epoch)
        nonce = self._hash_func(raw_nonce)

        # Obtain the sibling hashes along with their left/right position info.
        siblings = []
        idx = self._if2idx[if_id] + relative_epoch
        while idx > 0:
            if idx % 2 == 0:
                siblings.append((True, self._nodes[idx - 1]))
            else:
                siblings.append((False, self._nodes[idx + 1]))
            idx = (idx - 1) // 2

        # Using the above fields, construct a RevInfo capnp as the proof.
        return RevocationInfo.from_values(
            self._isd_as, if_id, epoch, nonce, siblings, prev_root, next_root,
            self._hash_type, self._ttl)


class ConnectedHashTree(object):
    """
    Class encapsulating a scion time-connected hash-tree.

    The number of interfaces and epoch times are configurable.
    The used hash function needs to implement the hashlib interface.

    """
    EPOCH_OK = 0
    EPOCH_NEAR_PAST = 1
    EPOCH_PAST = 2
    EPOCH_FUTURE = 3

    def __init__(self, isd_as, if_ids, seed, hashtree_ttl, hash_type):  # pragma: no cover
        """
        :param ISD_AS isd_as: The ISD_AS of the AS.
        :param List[int] if_ids: list of interface IDs of the AS.
        :param List[str] seeds: list of 3 seeds for creating hash-tree nonces.
        :param int hashtree_ttl: The TTL of each hash tree (in seconds).
        :param hash_type: Hash function type.
        """
        assert len(if_ids), "Must have at least 1 leaf"
        assert hashtree_ttl > 0, "HashTree TTL cannot be <= 0"
        ttl_window = self.get_ttl_window(hashtree_ttl)
        seed1 = seed + (ttl_window - 1).to_bytes(8, 'big')
        seed2 = seed + (ttl_window + 0).to_bytes(8, 'big')
        seed3 = seed + (ttl_window + 1).to_bytes(8, 'big')

        self._hash_func = hash_func_for_type(hash_type)
        self._ht0_root = self._hash_func(str(seed1).encode('utf-8'))
        self._ht1 = HashTree(isd_as, if_ids, seed2, hashtree_ttl, hash_type)
        self._ht2 = HashTree(isd_as, if_ids, seed3, hashtree_ttl, hash_type)

    @classmethod
    def get_ttl_window(cls, ttl):
        return int(time.time()) // ttl

    @classmethod
    def get_current_epoch(cls):
        return int(time.time()) // HASHTREE_EPOCH_TIME

    @classmethod
    def get_time_since_epoch(cls):
        return time.time() % HASHTREE_EPOCH_TIME

    @classmethod
    def time_until_next_window(cls, ttl):
        return ttl - (time.time() % ttl)

    @classmethod
    def get_next_tree(cls, isd_as, if_ids, seed, ttl, hash_type):
        ttl_window = cls.get_ttl_window(ttl) + 2
        seed += ttl_window.to_bytes(8, 'big')
        return HashTree(isd_as, if_ids, seed, ttl, hash_type)

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
        root12 = self._hash_func(root1 + root2)
        return root12

    def get_proof(self, if_id):
        # Call get_proof on the hashtree at T, passing roots for T-1 and T+1.
        epoch = ConnectedHashTree.get_current_epoch()
        return self._ht1.get_proof(
            if_id, epoch, self._ht0_root, self._ht2._nodes[0])

    @classmethod
    def get_possible_hashes(cls, rev_info):
        """
        Compute the hashes of the connected hash-tree roots given rev_info.
        """
        proof = rev_info.p
        assert proof.treeTTL > 0, "proof.TreeTTL <= 0 (%d)" % proof.treeTTL
        assert proof.treeTTL % 10 == 0, "proof.TreeTTL not multiple of 10 (%d)" % proof.treeTTL
        hash_func = hash_func_for_type(proof.hashType)
        n_epochs = proof.treeTTL // HASHTREE_EPOCH_TIME
        # Calculate the hashes upwards till the tree root (of T).
        relative_epoch = proof.epoch % n_epochs
        if_tuple = struct.pack("!qq", proof.ifID, relative_epoch) + proof.nonce
        curr_hash = hash_func(if_tuple)

        for i in range(len(proof.siblings)):
            is_left = proof.siblings[i].isLeft
            sibling_hash = proof.siblings[i].hash
            if is_left:
                curr_hash = sibling_hash + curr_hash
            else:
                curr_hash = curr_hash + sibling_hash
            curr_hash = hash_func(curr_hash)

        # Get the hashes for the tree joins T-1:T and T:T+1 and return them.
        hash01 = hash_func(proof.prevRoot + curr_hash)
        hash12 = hash_func(curr_hash + proof.nextRoot)
        return (hash01, hash12)

    @classmethod
    def verify(cls, rev_info, root):  # pragma: no cover
        """
        Verify whether rev_info proves the revocation for the current epoch,
        given the root of the connected hash-tree.

        :param RevInfo rev_info: proof for the revocation.
        :param bytes root: hash of the root, used for validating the proof.
        """
        assert not isinstance(rev_info.p, bytes), type(rev_info.p)
        h01, h12 = cls.get_possible_hashes(rev_info)
        return h01 == root or h12 == root

    @classmethod
    def verify_epoch(cls, epoch, cur_epoch=None):
        if not cur_epoch:
            cur_epoch = cls.get_current_epoch()
        gap_time = cls.get_time_since_epoch()
        if (epoch == cur_epoch or
                cur_epoch == epoch + 1 and gap_time < HASHTREE_EPOCH_TOLERANCE):
            return cls.EPOCH_OK
        if epoch < cur_epoch - 1:
            return cls.EPOCH_PAST
        if epoch < cur_epoch:
            return cls.EPOCH_NEAR_PAST
        return cls.EPOCH_FUTURE
