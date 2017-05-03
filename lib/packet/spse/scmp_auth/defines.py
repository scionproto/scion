# Copyright 2017 ETH Zurich
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
:mod:`defines` --- SCMPAuth extension definitions
=================================================================
"""
# Stdlib

# SCION
from lib.packet.spse.defines import SPSELengths

# max height of the hash tree
MAX_HEIGHT = 24


class SCMPAuthLengths:
    """
    SCMPAuth extension constant lengths.
    """

    # DRKey
    DIRECTION = 1
    MAC = 16
    PADDING = 3
    DRKEY_TOTAL_LENGTH = SPSELengths.SECMODE + DIRECTION + PADDING + MAC

    # HashTree
    HASH = 16
    HEIGHT = 1
    ORDER = 3
    SIGNATURE = 64
    HASH_TREE_MIN_LENGTH = SPSELengths.SECMODE + HEIGHT + ORDER + SIGNATURE


class SCMPAuthDirections:
    """
    SCMPAuthDRKey extension direction defines.
    """
    AS_TO_AS = 0  # Authenticated with S -> D
    AS_TO_HOST = 1  # Authenticated with S -> D:HD
    HOST_TO_HOST = 2  # Authenticated with S:HS -> D:HD
    HOST_TO_AS = 3  # Authenticated with D -> S:HS
    AS_TO_AS_REVERSED = 4  # Authenticated with D -> S
    HOST_TO_HOST_REVERSED = 5  # Authenticated with D:HD -> S:HS

    @staticmethod
    def is_valid_direction(direction):
        """
        Check if a valid direction has been provided.

        :param int direction: Direction value.
        :returns: If the direction is valid.
        :rtype: bool
        """
        return 0 <= direction <= 5
