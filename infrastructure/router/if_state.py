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
:mod:`if_state` --- Router interface state
==========================================
"""


class InterfaceState(object):
    """
    Class to store the interface state of the other edge routers, along with
    the corresponding current revocation token and proof.
    """
    def __init__(self):
        self.is_active = True
        self.rev_token = None

    def update(self, ifstate):
        """
        Updates the interface state.

        :param ifstate: IFStateInfo object sent by the BS.
        :type ifstate: :class: `lib.packet.path_mgmt.IFStateInfo`
        """
        assert isinstance(ifstate.rev_info.rev_token, bytes)
        self.is_active = bool(ifstate.state)
        self.rev_token = ifstate.rev_info.rev_token
