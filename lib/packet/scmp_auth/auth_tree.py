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
:mod:`auth_tree` --- SCMP Authentication hash-tree implementation
==================================================================
"""
# Stdlib
import struct
import time

# External
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# SCION
from lib.crypto.asymcrypto import sign, verify

HASH_CONSTANT = b"\xb0\xde[:Ue\xbf\xde\x10\x85'*\x17\xec\xb7\\"


class AuthTree(object):
    """
    Class encapsulating a auth hash-tree.
    The used hash function needs to implement the hashlib interface.
    """
    MAX_COUNT = 1024

    def __init__(self, packets, signing_key, number_of_packets):
        """
        :param List[bytes] packets: list of packets to be authenticated by AS.
        """
        self._signature = None
        self._nodes = None
        self._depth = 0
        self._leaves_start_idx = 0
        self._number_of_packets = number_of_packets
        self._setup(packets, signing_key)

    def _setup(self, packets, signing_key):
        assert self._number_of_packets > 0

        self._depth = self._calc_tree_depth(self._number_of_packets)
        self._create_tree(packets, signing_key)

    def _calc_tree_depth(self, leaf_count):
        """
        Calculate the depth of the smallest complete binary tree that can
        have at least 'leaf_count' leaves.

        :param int leaf_count: Count of leaves the tree should at least have.
        """
        depth = 0
        power_of_two = 1
        while power_of_two < leaf_count:
            depth += 1
            power_of_two *= 2
        return depth

    def _create_tree(self, packets, signing_key):
        """
        Create a (heap-like) array of nodes to represent the hash-tree.

        :param List[bytes] packets: list of packets to be authenticated by AS.
        :param bytes signing_key: private key to sign root hash
        """
        self._nodes = []
        node_count = pow(2, self._depth + 1) - 1
        for i in range(node_count):
            self._nodes.append(b"")

        # Compute and fill in the hash values for the leaves (left to right).
        self._leaves_start_idx = pow(2, self._depth) - 1
        idx = self._leaves_start_idx
        for packet in packets:
            self._nodes[idx] = packet_hash_func(packet)
            idx += 1

        filler = packet_hash_func(b"0")
        while idx < node_count:
            self._nodes[idx] = filler
            idx += 1

        for idx in reversed(range(self._leaves_start_idx)):
            self._nodes[idx] = in_tree_hash_func(self._nodes[idx * 2 + 1], self._nodes[idx * 2 + 2])

        self._signature = sign(self._nodes[0], signing_key)

    def get_proof(self, packet_idx):
        """
        Obtain the proof for a given packet in the hash-tree

        :param int packet_idx: Position of packet in list used to create hash-tree
        """

        idx = self._leaves_start_idx + packet_idx

        hashes = []
        order = []

        while idx > 0:
            if idx & 0x1:  # node is left child
                hashes.append(self._nodes[idx + 1])
                order.append(1)
            else:
                hashes.append(self._nodes[idx - 1])
                order.append(0)
            idx = int((idx-1)/2)

        return self._signature, hashes, order

    @staticmethod
    def verify(packet, signature, verifying_key, hashes, order):
        """
        Verify that hashing results in the same root as signed.

        :param bytes packet: received packet
        :param bytes signature: received signature
        :param bytes verifying_key: public key to verify signature
        :param List[bytes] hashes: received hashes
        :param List[int] order: received order
        :return:
        """

        tmp_hash = packet_hash_func(packet)

        for i, hash in enumerate(hashes):
            if order[i]:
                tmp_hash = in_tree_hash_func(tmp_hash, hash)
            else:
                tmp_hash = in_tree_hash_func(hash, tmp_hash)

        return verify(tmp_hash, signature, verifying_key)


def packet_hash_func(packet):
    return SHA256.new(packet).digest()[:16]


def in_tree_hash_func(hash_left, hash_right):
    aes = AES.new(hash_left + hash_right)  # Create 256 bit AES
    return aes.encrypt(HASH_CONSTANT)
