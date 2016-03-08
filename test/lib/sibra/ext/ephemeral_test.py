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
:mod:`ephemeral_test` --- lib.sibra.ext.ephemeral unit tests
============================================================
"""
# Stdlib
from unittest.mock import call, patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.sibra.ext.ephemeral import SibraExtEphemeral
from lib.types import RouterFlag
from test.testcommon import assert_these_calls, create_mock


class TestSibraExtEphemeralParse(object):
    """
    Unit tests for lib.sibra.ext.ephemeral.SibraExtEphemeral._parse
    """
    def test(self):
        inst = SibraExtEphemeral()
        inst._parse_start = create_mock()
        inst._parse_start.return_value = "data", "req"
        inst._parse_path_id = create_mock()
        inst._parse_path_id.side_effect = ["path id%s" % i for i in range(3)]
        inst._update_idxes = create_mock()
        inst._parse_active_blocks = create_mock()
        inst._parse_end = create_mock()
        inst.path_lens = [3, 4, 0]
        # Call
        inst._parse("raw")
        # Tests
        inst._parse_start.assert_called_once_with("raw")
        assert_these_calls(inst._parse_path_id, [
            call("data", False), call("data"), call("data")])
        inst._update_idxes.assert_called_once_with()
        ntools.eq_(inst.path_ids, ["path id0", "path id1", "path id2"])
        inst._parse_active_blocks.assert_called_once_with("data")
        ntools.eq_(inst.active_blocks, inst._parse_active_blocks.return_value)
        inst._parse_end.assert_called_once_with("data", "req")


class TestSibraExtEphemeralParseActiveBlocks(object):
    """
    Unit tests for
    lib.sibra.ext.ephemeral.SibraExtEphemeral._parse_active_blocks
    """
    def test_non_setup(self):
        inst = SibraExtEphemeral()
        inst._parse_block = create_mock()
        inst.setup = False
        inst.total_hops = 9
        # Call
        ntools.eq_(inst._parse_active_blocks("data"),
                   [inst._parse_block.return_value])
        # Tests
        inst._parse_block.assert_called_once_with("data", 9)

    def test_setup(self):
        inst = SibraExtEphemeral()
        inst.setup = True
        inst._parse_block = create_mock()
        inst._parse_block.side_effect = "block0", "block1"
        inst.path_lens = [3, 4, 0]
        # Call
        ntools.eq_(inst._parse_active_blocks("data"), ["block0", "block1"])
        # Tests
        assert_these_calls(inst._parse_block,
                           [call("data", 3), call("data", 4)])


class TestSibraExtEphemeralSetupFromValues(object):
    """
    Unit tests for lib.sibra.ext.ephemeral.SibraExtEphemeral.setup_from_values
    """
    @patch("lib.sibra.ext.ephemeral.SibraExtEphemeral._set_size", autospec=True)
    @patch("lib.sibra.ext.ephemeral.SibraExtEphemeral._parse_src_ia",
           autospec=True)
    @patch("lib.sibra.ext.ephemeral.SibraExtEphemeral._calc_total_hops",
           autospec=True)
    @patch("lib.sibra.ext.ephemeral.ResvBlockEphemeral", autospec=True)
    def test(self, resvblk, total_hops, parse_src_ia, set_size):
        steady_blocks = []
        for i in 3, 4, 1:
            b = create_mock(["num_hops"])
            b.num_hops = i
            steady_blocks.append(b)
        # Call
        inst = SibraExtEphemeral.setup_from_values(
            "req info", "path id", ["steady 0", "steady 1", "steady 2"],
            steady_blocks)
        # Tests
        ntools.assert_is_instance(inst, SibraExtEphemeral)
        ntools.eq_(inst.steady, False)
        ntools.eq_(inst.path_lens, [3, 4, 1])
        total_hops.assert_called_once_with(inst)
        ntools.eq_(inst.path_ids,
                   ["path id", "steady 0", "steady 1", "steady 2"])
        ntools.eq_(inst.active_blocks, steady_blocks)
        resvblk.from_values.assert_called_once_with("req info", 0)
        ntools.eq_(inst.req_block, resvblk.from_values.return_value)
        parse_src_ia.assert_called_once_with(inst)
        set_size.assert_called_once_with(inst)


class TestSibraExtEphemeralCalcTotalHops(object):
    """
    Unit tests for lib.sibra.ext.ephemeral.SibraExtEphemeral._calc_total_hops
    """
    def _check(self, path_lens, expected):
        inst = SibraExtEphemeral()
        inst.setup = True
        inst.path_lens = path_lens
        # Call
        inst._calc_total_hops()
        # Tests
        ntools.eq_(inst.total_hops, expected)

    def test(self):
        for path_lens, expected in (
            ([2, 0, 0], 2), ([2, 2, 0], 3), ([2, 3, 4], 7),
        ):
            yield self._check, path_lens, expected


class TestSibraExtEphemeralUpdateIdxes(object):
    """
    Unit tests for lib.sibra.ext.ephemeral.SibraExtEphemeral._update_idxes
    """
    @patch("lib.sibra.ext.ephemeral.SibraExtBase._update_idxes",
           autospec=True)
    def test_not_setup(self, super_update):
        inst = SibraExtEphemeral()
        inst.setup = False
        # Call
        inst._update_idxes()
        # Tests
        super_update.assert_called_once_with(inst)

    def _check_setup(self, path_lens, sof_idx, b_idx, rel_s_idx, curr_hop):
        inst = SibraExtEphemeral()
        inst.setup = True
        inst.path_lens = path_lens
        inst.sof_idx = sof_idx
        # Call
        inst._update_idxes()
        # Tests
        ntools.eq_(inst.block_idx, b_idx)
        ntools.eq_(inst.rel_sof_idx, rel_s_idx)
        ntools.eq_(inst.curr_hop, curr_hop)

    def test_setup(self):
        for sof_idx, b_idx, rel_s_idx, curr_hop in (
            (0, 0, 0, 0), (1, 0, 1, 1), (2, 1, 0, 1),
            (3, 1, 1, 2), (4, 1, 2, 3), (5, 2, 0, 3),
            (6, 2, 1, 4), (8, 2, 3, 6),
        ):
            yield (self._check_setup, [2, 3, 4], sof_idx, b_idx, rel_s_idx,
                   curr_hop)

    def test_error(self):
        inst = SibraExtEphemeral()
        inst.setup = True
        inst.path_lens = [2, 3, 4]
        inst.sof_idx = 9
        # Call
        ntools.assert_raises(AssertionError, inst._update_idxes)


class TestSibraExtEphemeralProcessSetup(object):
    """
    Unit tests for lib.sibra.ext.ephemeral.SibraExtEphemeral._process_setup
    """
    @patch("lib.sibra.ext.ephemeral.SibraExtBase._process_setup", autospec=True)
    def test_egress_forward(self, super_process):
        inst = SibraExtEphemeral()
        inst.get_next_ifid = create_mock()
        meta = create_mock(["from_local_as"])
        # Call
        ntools.eq_(inst._process_setup(meta),
                   [(RouterFlag.FORWARD, inst.get_next_ifid.return_value)])
        # Tests
        super_process.assert_called_once_with(inst, meta)

    @patch("lib.sibra.ext.ephemeral.SibraExtBase._process_setup", autospec=True)
    def test_ingress_deliver(self, super_process):
        inst = SibraExtEphemeral()
        inst._setup_switch_block = create_mock()
        inst.get_next_ifid = create_mock()
        inst.get_next_ifid.return_value = 0
        meta = create_mock(["from_local_as"])
        meta.from_local_as = False
        # Call
        ntools.eq_(inst._process_setup(meta), [(RouterFlag.DELIVER,)])
        # Tests
        inst._setup_switch_block.assert_called_once_with()


class TestSibraExtEphemeralSetupSwitchBlock(object):
    """
    Unit tests for
    lib.sibra.ext.ephemeral.SibraExtEphemeral._setup_switch_block
    """
    def _check(self, fwd, b_idx, rel_s_idx, expected):
        inst = SibraExtEphemeral()
        inst._update_idxes = create_mock()
        inst.fwd = fwd
        inst.block_idx = b_idx
        inst.rel_sof_idx = rel_s_idx
        inst.sof_idx = 0
        for i in 2, 3, 4:
            block = create_mock(["num_hops"])
            block.num_hops = i
            inst.active_blocks.append(block)
        # Call
        inst._setup_switch_block()
        # Tests
        ntools.eq_(inst.sof_idx, expected)
        if expected != 0:
            inst._update_idxes.assert_called_once_with()

    def test_fwd(self):
        for b_idx, rel_s_idx, expected in (
            (0, 0, 0), (0, 1, 1), (1, 0, 0), (1, 1, 0),
            (1, 2, 1), (2, 0, 0), (2, 3, 0),
        ):
            yield self._check, True, b_idx, rel_s_idx, expected

    def test_rev(self):
        for b_idx, rel_s_idx, expected in (
            (0, 0, 0), (0, 1, 0), (1, 0, -1), (1, 1, 0),
            (1, 2, 0), (2, 0, -1), (2, 3, 0),
        ):
            yield self._check, False, b_idx, rel_s_idx, expected


class TestSibraExtEphemeralAddHop(object):
    """
    Unit tests for lib.sibra.ext.ephemeral.SibraExtEphemeral._add_hop
    """
    @patch("lib.sibra.ext.ephemeral.SibraExtBase._add_hop", autospec=True)
    def test_non_setup(self, super_add_hop):
        inst = SibraExtEphemeral()
        inst.setup = False
        # Call
        inst._add_hop("key")
        # Tests
        super_add_hop.assert_called_once_with(inst, "key")

    def test_setup_old_block(self):
        inst = SibraExtEphemeral()
        inst._get_ifids = create_mock()
        inst._get_ifids.return_value = "ingress", "egress"
        inst._get_prev_raw = create_mock()
        inst.setup = True
        block = create_mock(["info", "sofs"])
        block.info = create_mock(["fwd_dir"])
        block.sofs = ["sof0"]
        inst.active_blocks = [block]
        inst.req_block = create_mock(["add_hop"])
        inst.path_ids = "path_ids"
        # Call
        inst._add_hop("key")
        # Tests
        inst._get_ifids.assert_called_once_with("sof0", block.info.fwd_dir)
        inst._get_prev_raw.assert_called_once_with(req=True)
        inst.req_block.add_hop.assert_called_once_with(
            "ingress", "egress", inst._get_prev_raw.return_value, "key",
            "path_ids")

    def test_setup_new_block(self):
        inst = SibraExtEphemeral()
        inst._get_ifids = create_mock()
        inst._get_ifids.side_effect = (
            ("prev_ingress", "prev_egress"),
            ("curr_ingress", "curr_egress"),
        )
        inst._get_prev_raw = create_mock()
        inst.setup = True
        inst.block_idx = 1
        inst.rel_sof_idx = 0
        prev_block = create_mock(["info", "sofs"])
        prev_block.info = create_mock(["fwd_dir"])
        prev_block.sofs = ["prev sof0", "prev sof1"]
        curr_block = create_mock(["info", "sofs"])
        curr_block.info = create_mock(["fwd_dir"])
        curr_block.sofs = ["curr sof0", "curr sof1"]
        inst.active_blocks = [prev_block, curr_block]
        inst.req_block = create_mock(["add_hop"])
        inst.path_ids = "path_ids"
        # Call
        inst._add_hop("key")
        # Tests
        assert_these_calls(inst._get_ifids, [
            call("prev sof1", prev_block.info.fwd_dir),
            call("curr sof0", curr_block.info.fwd_dir),
        ])
        inst.req_block.add_hop.assert_called_once_with(
            "prev_ingress", "curr_egress", inst._get_prev_raw.return_value,
            "key", "path_ids")


class TestSibraExtEphemeralVerifySof(object):
    """
    Unit tests for lib.sibra.ext.ephemeral.SibraExtEphemeral._verify_sof
    """
    @patch("lib.sibra.ext.ephemeral.SibraExtBase._verify_sof", autospec=True)
    def test_non_setup(self, super_verify):
        inst = SibraExtEphemeral()
        inst.setup = False
        inst.path_ids = "path ids"
        # Call
        ntools.eq_(inst._verify_sof("key"), super_verify.return_value)
        # Tests
        super_verify.assert_called_once_with(inst, "key", "path ids")

    @patch("lib.sibra.ext.ephemeral.SibraExtBase._verify_sof", autospec=True)
    def test_setup(self, super_verify):
        inst = SibraExtEphemeral()
        inst.setup = True
        inst.block_idx = 1
        inst.path_ids = ["eph id", "steady 0", "steady 1"]
        # Call
        inst._verify_sof("key")
        # Tests
        super_verify.assert_called_once_with(inst, "key", ["steady 1"])

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
