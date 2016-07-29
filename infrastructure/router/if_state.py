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
    Class to store the interface state of the other border routers, along with
    the corresponding current revocation token and proof.
    """
    def __init__(self):
        self.is_active = True
        self.rev_info = None

    def update(self, info):
        """
        Updates the interface state.

        :param info: IFStateInfo object sent by the BS.
        """
        self.is_active = info.p.active
        self.rev_info = info.rev_info
