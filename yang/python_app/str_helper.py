"""
:mod:`str_helper` -- YANG string helper functions
=================================================
"""
##################################################
# Copyright 2019 ETH Zurich
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
##################################################
##################################################
# This script uses sysrepo swig module in order to take the configuration for
# one ISD-AS.
# It suscribes for changes on the topology data-store and writes the
# topology.json file
# into every service directory (i.e. Border routers, beacon servers, ...).
##################################################
##################################################
# Author: Jordi Subira
# Email: jonieto@student.ethz.ch
##################################################
import string


def conversion_helper(yang_str: str) -> str:
    """Convert from yang module syntax to topology.json syntax."""

    # E.g converting isd-as -> to Isd_as ;
    if yang_str in ("isd-as", "mtu"):
        return yang_str.replace('-', '_').upper()
    # from border-routers to BorderRouters
    yang_str = string.capwords(yang_str, '-')
    return yang_str.replace('-', '')


def get_key_list_path(x_path: str) -> str:
    """Get the key from the path, which defines the entry in the list."""

    # Asuming one key at the moment
    return x_path.split("'")[-2]


def erase_prefix(yang_str: str) -> str:
    """Erase YANG module prefix."""

    return yang_str.split(":")[1]


def get_last_node_name(x_path: str) -> str:
    """Get the last node name on the x_path provided."""

    last_node = x_path.split(":")[-1].split("/")[-1]  # type: str
    last_node = conversion_helper(last_node)
    return last_node


def get_value_identityref(id_ref_val: str) -> str:
    """Strip off module prefix of identity-ref."""

    return id_ref_val.split("-")[-1]
