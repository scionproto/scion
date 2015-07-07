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


class HashChainExhausted(Exception):
    """The hash chain is exhausted"""
    pass


class HashChain(object):
    """
    Class encapsulating a generic hash-chain.

    The start and length of the chain as well as the hash function used are
    configurable. The used hash function needs to implement the hashlib
    interface.

    :ivar _start_ele:
    :type _start_ele:
    :ivar _length:
    :type _length:
    :ivar _hash_func:
    :type _hash_func:
    :ivar _next_ele_ptr:
    :type _next_ele_ptr:
    :ivar entries:
    :type entries:
    """

    def __init__(self, start_ele, length=50, hash_func=SHA256):
        """
        Initialize an instance of the class HashChain.

        :param start_ele:
        :type start_ele:
        :param length:
        :type length:
        :param hash_func:
        :type hash_func:
        """
        assert length > 1, "Hash chain must be at least length 2."
        self._start_ele = start_ele
        self._length = length
        self._hash_func = hash_func
        self._next_ele_ptr = length - 1
        self.entries = []
        self._init_chain()

    def _init_chain(self):
        """
        Initialize the hash chain.
        """
        prev_ele = self._start_ele
        self.entries.append(self._start_ele)
        for _ in range(self._length - 1):
            next_ele = self._hash_func.new(prev_ele).digest()
            self.entries.append(next_ele)
            prev_ele = next_ele

        # Initialize to first element.
        self._next_ele_ptr = self._length - 2

    def current_element(self):
        """
        Return the currently used element or 'None'.
        """
        if self._next_ele_ptr < 0 or self._next_ele_ptr >= self._length - 1:
            return None
        return self.entries[self._next_ele_ptr + 1]

    def next_element(self):
        """
        Return the next element in the hash chain or 'None' if the chain is
        empty.
        """
        if self._next_ele_ptr < 0:
            return None
        return self.entries[self._next_ele_ptr]

    def move_to_next_element(self):
        """
        Adjusts the internal pointer s.t. current_element() returns the next
        element.

        :raises:
            HashChainExhausted: if there are no more elements in the chain
        """
        if self._next_ele_ptr == 0:
            raise HashChainExhausted
        self._next_ele_ptr -= 1

    @staticmethod
    def verify(start_ele, target_ele, max_tries=50, hash_func=SHA256):
        """
        Verify that a given element belongs to a hash chain.

        :param start_ele: the starting element for verification
        :type start_ele: bytes
        :param target_ele: the target element, i.e. the one that needs to be
                           verified
        :type target_ele: bytes
        :param max_tries: the maximum number of tries before aborting the search
        :type max_tries: int
        :param hash_func: the hash function to be used (must implement the
                          hashlib interface)
        :type hash_func: object
        """
        cur_ele = start_ele
        for _ in range(max_tries):
            if cur_ele == target_ele:
                return True
            cur_ele = hash_func.new(cur_ele).digest()
        return False
