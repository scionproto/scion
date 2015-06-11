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
:mod:`hash_chain` --- Generic hash-chain implementation
=======================================================
"""

from Crypto.Hash import SHA256


class HashChain(object):
    """
    Class encapsulating a generic hash-chain.

    The start and length of the chain as well as the hash function used are
    configurable. The used hash function needs to implement the hashlib
    interface.
    """
    def __init__(self, start_ele, length=50, hash_func=SHA256):
        assert length > 1, "Hash chain must be at least length 2."
        self._start_ele = start_ele
        self._length = length
        self._hash_func = hash_func
        self._next_ele_ptr = length - 1
        self.entries = []

        self._init_chain()

    def _init_chain(self):
        """
        Initializes the hash chain.
        """
        prev_ele = self._start_ele
        self.entries.append(self._start_ele)
        for _ in range(self._length - 1):
            next_ele = self._hash_func.new(prev_ele).digest()
            self.entries.append(next_ele)
            prev_ele = next_ele

    def current_element(self):
        """
        Returns the currently used element or 'None'.
        """
        if self._next_ele_ptr < 0 or self._next_ele_ptr >= self._length - 1:
            return None

        return self.entries[self._next_ele_ptr + 1]

    def next_element(self):
        """
        Returns the next element in the hash chain or 'None' if the chain is
        empty.
        """
        if self._next_ele_ptr < 0:
            return None
        next_ele = self.entries[self._next_ele_ptr]
        self._next_ele_ptr -= 1
        return next_ele

    @staticmethod
    def verify(start_ele, target_ele, max_tries=50, hash_func=SHA256):
        """
        Verifies that a given element belongs to a hash chain.

        :param start_ele: the starting element for verification
        :type: bytes
        :param target_ele: the target element, i.e. the one that needs to be
                           verified
        :type: bytes
        :param max_tries: the maximum number of tries before aborting the search
        :type: int
        :param hash_func: the hash function to be used (must implement the
                          hashlib interface)
        :type: object
        """
        cur_ele = start_ele
        for _ in range(max_tries):
            if cur_ele == target_ele:
                return True
            cur_ele = hash_func.new(cur_ele).digest()

        return False
