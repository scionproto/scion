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
from lib.sibra.ext.steady import (
    SibraExtSteady,
)
from lib.types import RouterFlag
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
        inst._parse_block.assert_called_once_with("data", 5, True)
        ntools.eq_(inst.active_blocks, [inst._parse_block.return_value])
        inst._parse_end.assert_called_once_with("data", "req")


class TestSibraExtSteadySetupFromValues(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady.setup_from_values
    """
    @patch("lib.sibra.ext.steady.SibraExtSteady._set_size", autospec=True)
    @patch("lib.sibra.ext.steady.ResvBlockSteady.from_values", autospec=True)
    def test(self, resv_fv, set_size):
        # Call
        inst = SibraExtSteady.setup_from_values(
            "req info", "total hops", "path id", "setup")
        # Tests
        ntools.assert_is_instance(inst, SibraExtSteady)
        ntools.eq_(inst.setup, "setup")
        ntools.eq_(inst.total_hops, "total hops")
        ntools.eq_(inst.path_ids, ["path id"])
        resv_fv.assert_called_once_with("req info", "total hops")
        ntools.eq_(inst.req_block, resv_fv.return_value)
        set_size.assert_called_once_with(inst)


class TestSibraExtSteadyUseFromValues(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady.use_from_values
    """
    @patch("lib.sibra.ext.steady.SibraExtSteady.switch_resv", autospec=True)
    def test(self, switch_resv):
        block = create_mock(["num_hops"])
        # Call
        inst = SibraExtSteady.use_from_values("path id", block)
        # Tests
        ntools.assert_is_instance(inst, SibraExtSteady)
        ntools.eq_(inst.path_ids, ["path id"])
        ntools.eq_(inst.total_hops, block.num_hops)
        switch_resv.assert_called_once_with(inst, [block])


class TestSibraExtSteadyPack(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady.pack
    """
    def test(self):
        inst = SibraExtSteady()
        inst._pack_start = create_mock()
        inst._pack_start.return_value = ["raw"]
        inst._pack_end = create_mock()
        inst.total_hops = 11
        # Call
        ntools.eq_(inst.pack(), inst._pack_end.return_value)
        # Tests
        inst._pack_end.assert_called_once_with(["raw", bytes([11, 0, 0])])


class TestSibraExtSteadyProcess(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady._process
    """
    def test_verify_fail(self):
        inst = SibraExtSteady()
        inst._verify_sof = create_mock()
        inst._verify_sof.return_value = False
        # Call
        ret = inst._process("state", "spkt", "dir_fwd", "key")
        # Tests
        inst._verify_sof.assert_called_once_with("key")
        ntools.eq_(ret[0][0], RouterFlag.ERROR)

    def test_setup(self):
        inst = SibraExtSteady()
        inst._verify_sof = create_mock()
        inst._process_setup = create_mock()
        inst._process_setup.return_value = ["a", "b"]
        inst.setup = True
        # Call
        ntools.eq_(inst._process("state", "spkt", "dir_fwd", "key"),
                   ["a", "b"])
        # Tests
        inst._process_setup.assert_called_once_with(
            "state", "spkt", "dir_fwd", "key")

    def test_use(self):
        inst = SibraExtSteady()
        inst._verify_sof = create_mock()
        inst._process_use = create_mock()
        inst._process_use.return_value = ["a", "b"]
        # Call
        ntools.eq_(inst._process("state", "spkt", "dir_fwd", "key"),
                   ["a", "b"])
        # Tests
        inst._process_use.assert_called_once_with("state", "spkt", "dir_fwd")

    def test_renew(self):
        inst = SibraExtSteady()
        inst._verify_sof = create_mock()
        inst._process_renewal = create_mock()
        inst._process_renewal.return_value = ["renew flag"]
        inst._process_use = create_mock()
        inst.req_block = True
        # Call
        ret = inst._process("state", "spkt", "dir_fwd", "key")
        # Tests
        ntools.eq_(ret[0], "renew flag")


class TestSibraExtSteadyProcessSetup(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady._process_setup
    """
    def test_rev_accepted(self):
        inst = SibraExtSteady()
        inst.fwd = False
        inst.accepted = True
        inst.path_ids = [9]
        state = create_mock(["steady_pend_confirm"])
        # Call
        ntools.eq_(inst._process_setup(state, "spkt", "dir_fwd", "key"), [])
        # Tests
        state.steady_pend_confirm.assert_called_once_with(9)

    def test_rev_rejected(self):
        inst = SibraExtSteady()
        inst.fwd = False
        inst.accepted = False
        inst.path_ids = [9]
        state = create_mock(["steady_pend_remove"])
        # Call
        ntools.eq_(inst._process_setup(state, "spkt", "dir_fwd", "key"), [])
        # Tests
        state.steady_pend_remove.assert_called_once_with(9)

    def test_fwd(self):
        inst = SibraExtSteady()
        inst.fwd = True
        inst._process_req = create_mock()
        # Call
        ntools.eq_(inst._process_setup("state", "spkt", "dir_fwd", "key"), [])
        # Tests
        inst._process_req.assert_called_once_with(
            "state", "spkt", "dir_fwd", "key")


class TestSibraExtSteadyProcessRenewal(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady._process_renewal
    """
    def test_rev_accepted(self):
        inst = SibraExtSteady()
        inst.fwd = False
        inst.accepted = True
        inst.path_ids = [9]
        inst.req_block = create_mock(["info"])
        # Call
        ntools.eq_(inst._process_renewal("state", "spkt", "dir_fwd", "key"), [])

    def test_rev_rejected_later(self):
        inst = SibraExtSteady()
        inst.fwd = False
        inst.accepted = False
        inst.path_ids = [9]
        inst.curr_hop = 4
        info = create_mock(["fail_hop", "index"])
        info.fail_hop = 5
        inst.req_block = create_mock(["info"])
        inst.req_block.info = info
        state = create_mock(["steady_idx_remove"])
        # Call
        ntools.eq_(inst._process_renewal(state, "spkt", "dir_fwd", "key"), [])
        # Tests
        state.steady_idx_remove.assert_called_once_with(9, info.index)

    def test_fwd(self):
        inst = SibraExtSteady()
        inst.fwd = True
        inst.accepted = True
        inst._process_req = create_mock()
        # Call
        ntools.eq_(inst._process_renewal("state", "spkt", "dir_fwd", "key"), [])
        # Tests
        inst._process_req.assert_called_once_with(
            "state", "spkt", "dir_fwd", "key", setup=False)


class TestSibraExtSteadyProcessUse(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady._process_use
    """
    @patch("lib.sibra.ext.steady.BWSnapshot", autospec=True)
    def test_dir_fwd_accepted(self, bwsnap):
        inst = SibraExtSteady()
        inst.get_next_ifid = create_mock()
        inst.path_ids = [9]
        block = create_mock(["info"])
        block.info = create_mock(["index"])
        inst.active_blocks = [block]
        state = create_mock(["steady_use"])
        # Call
        ntools.eq_(inst._process_use(state, "spkt", True),
                   [(RouterFlag.FORWARD, inst.get_next_ifid.return_value)])
        # Tests
        ntools.assert_false(bwsnap.reverse.called)
        bwsnap.assert_called_once_with(4 * 8)
        state.steady_use.assert_called_once_with(
            9, block.info.index, bwsnap.return_value)

    @patch("lib.sibra.ext.steady.BWSnapshot", autospec=True)
    def test_dir_rev_rejected(self, bwsnap):
        inst = SibraExtSteady()
        inst.path_ids = [9]
        block = create_mock(["info"])
        block.info = create_mock(["index"])
        inst.active_blocks = [block]
        state = create_mock(["steady_use"])
        state.steady_use.return_value = False
        # Call
        ret = inst._process_use(state, "spkt", False)
        # Tests
        bwsnap.return_value.reverse.assert_called_once_with()
        ntools.eq_(ret[0][0], RouterFlag.ERROR)


class TestSibraExtSteadyProcessReq(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady._process_req
    """
    def _setup(self, accepted=True, bwhint=None):
        inst = SibraExtSteady()
        inst.accepted = accepted
        bwsnap = create_mock(["reverse"])
        req_info = create_mock(["bw", "index", "exp_tick"])
        req_info.bw = create_mock(["to_snap"])
        req_info.bw.to_snap.return_value = bwsnap
        inst.req_block = create_mock(["info"])
        inst.req_block.info = req_info
        state = create_mock(["steady_add"])
        state.steady_add.return_value = bwhint
        inst.path_ids.append("path id 0")
        inst._req_accepted = create_mock()
        inst._req_denied = create_mock()
        return inst, bwsnap, req_info, state

    def test_fwd_accepted_to_accepted(self):
        inst, bwsnap, req_info, state = self._setup()
        # Call
        inst._process_req(state, "spkt", True, "key", "setup")
        # Tests
        ntools.assert_false(bwsnap.reverse.called)
        state.steady_add.assert_called_once_with(
            "path id 0", req_info.index, bwsnap, req_info.exp_tick, True,
            "setup")
        inst._req_accepted.assert_called_once_with("spkt", True, "key")
        ntools.assert_false(inst._req_denied.called)

    def test_rev_accepted_to_denied(self):
        inst, bwsnap, req_info, state = self._setup(bwhint="bwhint")
        # Call
        inst._process_req(state, "spkt", False, "key")
        # Tests
        bwsnap.reverse.assert_called_once_with()
        state.steady_add.assert_called_once_with(
            "path id 0", req_info.index, bwsnap, req_info.exp_tick, True, True)
        ntools.assert_false(inst._req_accepted.called)
        inst._req_denied.assert_called_once_with(False, "bwhint")

    def test_fwd_not_accepted(self):
        inst, bwsnap, req_info, state = self._setup(
            accepted=False, bwhint="bwhint")
        # Call
        inst._process_req(state, "spkt", True, "key", setup=False)
        # Tests
        state.steady_add.assert_called_once_with(
            "path id 0", req_info.index, bwsnap, req_info.exp_tick, False,
            False)
        ntools.assert_false(inst._req_accepted.called)
        inst._req_denied.assert_called_once_with(True, "bwhint")


class TestSibraExtSteadyReqAccepted(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady._req_accepted
    """
    def _check(self, fwd, curr_hop, total_hops, add_hop):
        inst = SibraExtSteady()
        inst._add_hop = create_mock()
        inst.curr_hop = curr_hop
        inst.total_hops = total_hops
        inst.path_ids = ["pid0", "pid1", "pid2"]
        # Call
        inst._req_accepted("spkt", fwd, "key")
        # Tests
        if add_hop:
            inst._add_hop.assert_called_once_with("spkt", "key", ["pid0"])
        else:
            ntools.assert_false(inst._add_hop.called)

    def test(self):
        for fwd, curr_hop, total_hop, add_hop in (
            (True, 0, 0, True),
            (False, 0, 2, False),
            (False, 1, 2, True),
            (False, 2, 2, False),
        ):
            yield self._check, fwd, curr_hop, total_hop, add_hop


class TestSibraExtSteadyReqDenied(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady._req_denied
    """
    def test_was_accepted(self):
        inst = SibraExtSteady()
        inst._reject_req = create_mock()
        # Call
        inst._req_denied(True, "bwhint")
        # Tests
        inst._reject_req.assert_called_once_with("bwhint")

    def _check_fwd(self, curr_hop, fail_hop, offer_hop):
        inst = SibraExtSteady()
        inst.accepted = False
        inst.curr_hop = curr_hop
        req = create_mock(["info", "offers"])
        req.offers = []
        for i in range(5):
            offer = create_mock(["min"])
            req.offers.append(offer)
        info = create_mock(["fail_hop"])
        info.fail_hop = fail_hop
        req.info = info
        inst.req_block = req
        # Call
        inst._req_denied(True, "bwhint")
        # Tests
        for i, offer in enumerate(req.offers):
            if i == offer_hop:
                offer.min.assert_called_once_with("bwhint")
            else:
                ntools.assert_false(offer.min.called)

    def test_fwd(self):
        for curr_hop, fail_hop, offer_hop in (
            (0, 0, 0), (1, 1, 0), (6, 3, 3),
        ):
            yield self._check_fwd, curr_hop, fail_hop, offer_hop

    def test_rev(self):
        inst = SibraExtSteady()
        inst.accepted = False
        inst.curr_hop = "curr hop"
        bwhint = create_mock(["reverse"])
        inst.req_block = create_mock(["add"])
        # Call
        inst._req_denied(False, bwhint)
        # Tests
        bwhint.reverse.assert_called_once_with()
        inst.req_block.add.assert_called_once_with("curr hop", bwhint)


class TestSibraExtSteadyRejectReq(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady._reject_req
    """
    @patch("lib.sibra.ext.steady.OfferBlockSteady", autospec=True)
    def test(self, offer):
        inst = SibraExtSteady()
        inst.curr_hop = 3
        inst.total_hops = 6
        old_req = create_mock(["info"])
        info = create_mock(["fail_hop"])
        old_req.info = info
        inst.req_block = old_req
        new_req = create_mock(["add"])
        offer.from_values.return_value = new_req
        inst._set_size = create_mock()
        # Call
        inst._reject_req("bwhint")
        # Tests
        ntools.assert_false(inst.accepted)
        ntools.eq_(info.fail_hop, 3)
        offer.from_values.assert_called_once_with(info, 4)
        new_req.add.assert_called_once_with(3, "bwhint")
        inst._set_size.assert_called_once_with()


class TestSibraExtSteadyAddHop(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady._add_hop
    """
    @patch("lib.sibra.ext.steady.SibraExtBase._add_hop", autospec=True)
    def test_non_setup(self, super_addhop):
        inst = SibraExtSteady()
        inst.setup = False
        # Call
        inst._add_hop("spkt", "key", "path ids")
        # Tests
        super_addhop.assert_called_once_with(inst, "key", "path ids")

    def _check_setup(self, up):
        inst = SibraExtSteady()
        inst.setup = True
        iof = create_mock(["up_flag"])
        iof.up_flag = up
        hof = create_mock(["egress_if", "ingress_if"])
        path = create_mock(["get_hof", "get_iof"])
        path.get_iof.return_value = iof
        path.get_hof.return_value = hof
        spkt = create_mock(["path"])
        spkt.path = path
        req = create_mock(["add_hop"])
        inst.req_block = req
        # Call
        inst._add_hop(spkt, "key", "path ids")
        # Tests
        if up:
            req.add_hop.assert_called_once_with(
                hof.egress_if, hof.ingress_if, "key", "path ids")
        else:
            req.add_hop.assert_called_once_with(
                hof.ingress_if, hof.egress_if, "key", "path ids")

    def test_setup(self):
        yield self._check_setup, True
        yield self._check_setup, False


class TestSibraExtSteadyVerifySof(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady._verify_sof
    """
    def _setup(self, verified=True):
        inst = SibraExtSteady()
        curr_sof = create_mock(["calc_mac", "mac"])
        curr_sof.mac = "abcd" if verified else "efgh"
        curr_sof.calc_mac.return_value = "abcd"
        block = create_mock(["info", "sofs"])
        block.sofs = [curr_sof]
        inst.active_blocks = [block]
        inst.path_ids = "path ids"
        inst._get_prev_raw = create_mock()
        return inst, block, curr_sof

    def test_success(self):
        inst, block, curr_sof = self._setup()
        # Call
        ntools.eq_(inst._verify_sof("key"), True)
        # Tests
        curr_sof.calc_mac.assert_called_once_with(
            block.info, "key", "path ids", inst._get_prev_raw.return_value)

    def test_failure(self):
        inst, block, curr_sof = self._setup(False)
        # Call
        ntools.eq_(inst._verify_sof("key"), False)


class TestSibraExtSteadyGetPrevRaw(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady._get_prev_raw
    """
    def _check(self, fwd_dir, curr_hop, expected):
        inst = SibraExtSteady()
        inst.curr_hop = curr_hop
        info = create_mock(["fwd_dir"])
        info.fwd_dir = fwd_dir
        block = create_mock(["info", "num_hops", "sofs"])
        block.info = info
        block.num_hops = 5
        block.sofs = []
        for i in range(block.num_hops):
            sof = create_mock(["pack"])
            sof.pack.return_value = "sof %d" % i
            block.sofs.append(sof)
        inst.active_blocks = [block]
        # Call
        ntools.eq_(inst._get_prev_raw(), expected)

    def test(self):
        for fwd_dir, curr_hop, expected in (
            (True, 0, None), (True, 1, "sof 0"), (True, 4, "sof 3"),
            (False, 0, "sof 1"), (False, 3, "sof 4"), (False, 4, None),
        ):
            yield self._check, fwd_dir, curr_hop, expected


class TestSibraExtSteadyGetNextIfid(object):
    """
    Unit tests for lib.sibra.ext.steady.SibraExtSteady.get_next_ifid
    """
    def test_setup(self):
        inst = SibraExtSteady()
        inst.setup = True
        # Call
        ntools.assert_is_none(inst.get_next_ifid())

    def _check_use(self, fwd, fwd_dir, exp_egress):
        inst = SibraExtSteady()
        inst.fwd = fwd
        sof = create_mock(["egress", "ingress"])
        inst.active_sof = create_mock()
        inst.active_sof.return_value = sof
        info = create_mock(["fwd_dir"])
        info.fwd_dir = fwd_dir
        block = create_mock(["info"])
        block.info = info
        inst.active_blocks = [block]
        expected = sof.egress if exp_egress else sof.ingress
        # Call
        ntools.eq_(inst.get_next_ifid(), expected)

    def test_use(self):
        for fwd, fwd_dir, exp_ingress in (
            (True, True, True), (True, False, False),
            (False, False, True), (False, True, False),
        ):
            yield self._check_use, fwd, fwd_dir, exp_ingress

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
