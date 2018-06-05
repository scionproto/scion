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
:mod:`util` --- utility functions
=================================
"""


def seg_to_hops(seg):
    """
    Extract the list of hops a path segment traverses, returns it as a tuple of
    tuples.
    """
    hops = []
    for asm in seg.iter_asms():
        hops.append(asm.isd_as())
    assert hops
    return tuple(hops)


def find_last_ifid(pkt, ext):
    """
    Find the interface a packet came from. Handles both SCION and SIBRA paths.
    """
    assert ext.steady
    if ext.setup:
        # Steady setup packets use SCION paths
        path = pkt.path
        iof = path.get_iof()
        hof = path.get_hof()
        if iof.cons_dir_flag:
            return hof.ingress_if
        else:
            return hof.egress_if
    sof = ext.active_blocks[0].sofs[ext.curr_hop]
    if ext.fwd:
        return sof.ingress
    else:
        return sof.egress
