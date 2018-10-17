# Copyright 2018 ETH Zurich
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


def _prom_addr_br(br_ele):
    """Get the prometheus address for a border router"""
    pub = _get_pub(br_ele['CtrlAddr'])
    return "[%s]:%s" % (pub['Public']['Addr'].ip, pub['Public']['L4Port'] + 1)


def _prom_addr_infra(infra_ele):
    """Get the prometheus address for an infrastructure element."""
    pub = _get_pub(infra_ele['Addrs'])
    return "[%s]:%s" % (pub['Public']['Addr'].ip, pub['Public']['L4Port'] + 1)


def _get_pub(topo_addr):
    pub = topo_addr.get('IPv6')
    if pub is not None:
        return pub
    return topo_addr['IPv4']
