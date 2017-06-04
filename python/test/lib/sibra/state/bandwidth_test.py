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
:mod:`bandwidth_test` --- lib.sibra.state.bandwidth unit tests
==============================================================
"""
# External packages
import nose
import nose.tools as ntools

# SCION
from lib.sibra.state.bandwidth import LinkBandwidth
from lib.sibra.util import BWSnapshot


class TestLinkBandwidthUpdate(object):
    """
    Unit tests for lib.sibra.state.bandwidth.LinkBandwidth.update

    Note: these tests do not mock out BWSnapshot, as it would make testing too
    complex to be useful.
    """
    def test(self):
        inst = LinkBandwidth("owner", BWSnapshot(100, 100))
        for i, bw in enumerate([50, 0, -10, -20, 0, 0, -20]):
            inst.resvs[i] = BWSnapshot(bw, bw)
        updates = []
        for idx, bw in [(0, -10), (1, -10), (2, +10), (6, 10)]:
            updates.append((idx, BWSnapshot(bw, bw)))
        # Call
        inst.update(updates)
        # Tests
        for i, bw in enumerate([40, -10, 0, -20, 0, 0, -10]):
            tick = BWSnapshot(bw, bw)
            ntools.eq_(inst.resvs[i], tick)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
