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
:mod:`errors` --- Router errors and exceptions
==============================================
"""

# SCION
from lib.errors import SCIONBaseError, SCIONBaseException


class SCIONIFVerificationError(SCIONBaseError):
    """
    The current hop field (ingress or egress, depending on context) interface
    does not match the interface of the border router.
    """


class SCIONOFVerificationError(SCIONBaseError):
    """
    Opaque field MAC verification error.
    """
    pass


class SCIONOFExpiredError(SCIONBaseError):
    """
    Opaque field expired error.
    """
    pass


class SCIONPacketHeaderCorruptedError(SCIONBaseError):
    """
    Packet header is in an invalid state.
    """
    pass


class SCIONInterfaceDownException(SCIONBaseException):
    """
    The interface to forward the packet to is down.
    """

    def __init__(self, if_id):
        super().__init__()
        self.if_id = if_id


class SCIONSegmentSwitchError(SCIONBaseException):
    """
    Switching from previous to current segment is disallowed.
    """
