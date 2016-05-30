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
:mod:`seg_recs_test` --- lib.packet.path_mgmt.seg_recs tests
=====================================================
"""
# Stdlib
from unittest.mock import patch, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.path_mgmt.seg_recs import PathSegmentRecords
from test.testcommon import assert_these_calls, create_mock


class TestPathSegmentRecordsFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.seg_recs.PathSegmentRecords.from_values
    """
    @patch("lib.packet.path_mgmt.seg_recs.PathSegment", autospec=True)
    def test(self, pseg):
        pcb_dict = {10: [], 20: []}
        pcbs = []
        for type_ in 10, 20:
            for i in range(2):
                pcb = create_mock(["pack"])
                pcb.pack.return_value = bytes("%d:%d" % (type_, i), "ascii")
                pcbs.append(pcb)
                pcb_dict[type_].append(pcb)
        # Call
        inst = PathSegmentRecords.from_values(pcb_dict)
        # Tests
        ntools.eq_(len(inst.p.pcbs), len(pcbs))
        ntools.eq_(len(inst.pcbs), 2)
        assert_these_calls(pseg, [call(b"10:0"), call(b"10:1"),
                                  call(b"20:0"), call(b"20:1")], any_order=True)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
