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
:mod:`steady_test` --- lib.sibra.ext.steady unit tests
======================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.sibra.ext.steady import SibraExtSteady
from test.testcommon import create_mock


class TestSibraExtSteadyParse(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady._parse
    """
    def test(self):
        inst = SibraExtSteady()
        inst._parse_start = create_mock()
        inst._parse_start.return_value = "data", "req"
        inst._parse_path_id = create_mock()
        inst._parse_block = create_mock()
        inst._parse_end = create_mock()
        inst.path_lens = [5, 0, 0]
        # Call
        inst._parse("raw")
        # Tests
        inst._parse_start.assert_called_once_with("raw")
        inst._parse_path_id.assert_called_once_with("data")
        ntools.eq_(inst.path_ids, [inst._parse_path_id.return_value])
        inst._parse_block.assert_called_once_with("data", 5)
        ntools.eq_(inst.active_blocks, [inst._parse_block.return_value])
        inst._parse_end.assert_called_once_with("data", "req")


class TestSibraExtSteadyAddHop(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady._add_hop
    """
    @patch("lib.sibra.ext.steady.SibraExtBase._add_hop", autospec=True)
    def test_non_setup(self, super_addhop):
        inst = SibraExtSteady()
        inst.setup = False
        # Call
        inst._add_hop("key")
        # Tests
        super_addhop.assert_called_once_with(inst, "key")

    def _check_setup(self, cons_dir):
        inst = SibraExtSteady()
        inst._get_prev_raw = create_mock()
        inst.setup = True
        inst.path_ids = "path ids"
        iof = create_mock(["cons_dir_flag"])
        iof.cons_dir_flag = cons_dir
        hof = create_mock(["egress_if", "ingress_if"])
        path = create_mock(["get_hof", "get_iof"])
        path.get_iof.return_value = iof
        path.get_hof.return_value = hof
        spkt = create_mock(["path"])
        spkt.path = path
        req = create_mock(["add_hop"])
        inst.req_block = req
        # Call
        inst._add_hop("key", spkt)
        # Tests
        if cons_dir:
            req.add_hop.assert_called_once_with(
                hof.ingress_if, hof.egress_if, inst._get_prev_raw.return_value,
                "key", "path ids")
        else:
            req.add_hop.assert_called_once_with(
                hof.egress_if, hof.ingress_if, inst._get_prev_raw.return_value,
                "key", "path ids")

    def test_setup(self):
        yield self._check_setup, True
        yield self._check_setup, False


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
