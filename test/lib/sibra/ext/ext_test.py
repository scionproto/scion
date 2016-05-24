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
:mod:`ext_test` --- lib.sibra.ext.ext unit tests
================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.sibra.ext.ext import (
    SibraExtBase,
)
from lib.types import RouterFlag
from test.testcommon import create_mock

FLAG_MAP = (
    # Steady setup accepted fwd
    (0b11101100, (True, True, True, False, True, True, 0), True),
    # Ephemeral setup denied rev
    (0b11000000, (True, True, False, False, False, False, 0), False),
    # Steady use error fwd
    (0b00111100, (False, False, True, True, True, True, 0), True),
)


class SibraExtBaseTesting(SibraExtBase):
    NAME = "SibraExtBaseTesting"
    STEADY = None

    def pack(self):
        pass


class TestSibraExtBaseParseStart(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._parse_start
    """
    @patch("lib.sibra.ext.ext.HopByHopExtension._parse", autospec=True)
    @patch("lib.sibra.ext.ext.Raw", autospec=True)
    def test(self, raw, super_parse):
        inst = SibraExtBaseTesting()
        inst._parse_flags = create_mock()
        inst._calc_total_hops = create_mock()
        data = create_mock(["pop"])
        data.pop.side_effect = "flags", "sof idx", bytes([4, 5, 0])
        raw.return_value = data
        # Call
        inst._parse_start("data")
        # Tests
        super_parse.assert_called_once_with(inst, "data")
        raw.assert_called_once_with("data", "SibraExtBaseTesting",
                                    inst.MIN_LEN, min_=True)
        inst._parse_flags.assert_called_once_with("flags")
        ntools.eq_(inst.sof_idx, "sof idx")
        ntools.eq_(inst.path_lens, [4, 5, 0])
        inst._calc_total_hops.assert_called_once_with()


class TestSibraExtBaseParseEnd(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._parse_end
    """
    def _setup(self, accepted=True):
        inst = SibraExtBaseTesting()
        inst.accepted = accepted
        inst._parse_block = create_mock()
        inst._parse_offers_block = create_mock()
        inst._parse_src_ia = create_mock()
        inst.total_hops = "total hops"
        inst.steady = "so steady"
        data = create_mock(["__len__"])
        data.__len__.return_value = 0
        return inst, data

    def test_req_accepted(self):
        inst, data = self._setup()
        # Call
        inst._parse_end(data, True)
        # Tests
        inst._parse_block.assert_called_once_with(
            data, "total hops", "so steady")
        ntools.eq_(inst.req_block, inst._parse_block.return_value)
        inst._parse_src_ia.assert_called_once_with()

    def test_req_rejected(self):
        inst, data = self._setup(accepted=False)
        # Call
        inst._parse_end(data, True)
        # Tests
        inst._parse_offers_block.assert_called_once_with(data)
        ntools.eq_(inst.req_block, inst._parse_offers_block.return_value)

    def test_data_remaining(self):
        inst, _ = self._setup()
        data = create_mock(["__len__", "get"])
        data.get.return_value = b"dead beef"
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse_end, data, False)


class TestSibraExtBaseParseFlags(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._parse_flags
    """
    def _check(self, flags, values, steady):
        inst = SibraExtBaseTesting()
        inst.STEADY = steady
        setup = values.pop(0)
        req = values.pop(0)
        # Call
        ntools.eq_(inst._parse_flags(flags), req)
        # Tests
        ntools.eq_(inst.setup, setup)
        ntools.eq_(inst.accepted, values.pop(0))
        ntools.eq_(inst.error, values.pop(0))
        ntools.eq_(inst.steady, values.pop(0))
        ntools.eq_(inst.fwd, values.pop(0))
        ntools.eq_(inst.version, values.pop(0))

    def test(self):
        for flags, values, steady in FLAG_MAP:
            yield self._check, flags, list(values), steady


class TestSibraExtBaseParseBlock(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._parse_block
    """
    @patch("lib.sibra.ext.ext.ResvBlockSteady", autospec=True)
    def test_steady(self, resvb):
        inst = SibraExtBaseTesting()
        data = create_mock(["pop"])
        # Call
        ntools.eq_(inst._parse_block(data, 5, True), resvb.return_value)
        # Tests
        data.pop.assert_called_once_with(6 * inst.LINE_LEN)
        resvb.assert_called_once_with(data.pop.return_value)

    @patch("lib.sibra.ext.ext.ResvBlockEphemeral", autospec=True)
    def test_ephemeral(self, resvb):
        inst = SibraExtBaseTesting()
        data = create_mock(["pop"])
        # Call
        ntools.eq_(inst._parse_block(data, 0, False), resvb.return_value)
        # Tests
        resvb.assert_called_once_with(data.pop.return_value)


class TestSibraExtBasePackEnd(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._pack_end
    """
    def test_min(self):
        inst = SibraExtBaseTesting()
        inst._check_len = create_mock()
        expected = b"input"
        # Call
        ntools.eq_(inst._pack_end([b"input"]), expected)
        # Tests
        inst._check_len.assert_called_once_with(b"input")

    def test_full(self):
        inst = SibraExtBaseTesting()
        inst.path_ids = [bytes(range(3)), bytes(range(5))]
        for i in range(2):
            block = create_mock(["pack"])
            block.pack.return_value = ("active%d" % i).encode("ascii")
            inst.active_blocks.append(block)
        inst.req_block = create_mock(["pack"])
        inst.req_block.pack.return_value = b"req"
        inst._check_len = create_mock()
        expected = b"".join([b"input", bytes(range(3)),
                             bytes(range(5)), b"active0", b"active1", b"req"])
        # Call
        ntools.eq_(inst._pack_end([b"input"]), expected)


class TestSibraExtBasePackFlags(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._pack_flags
    """
    def _check(self, expected, flags, steady):
        inst = SibraExtBaseTesting()
        inst.STEADY = steady
        inst.setup = flags.pop(0)
        inst.req_block = flags.pop(0)
        inst.accepted = flags.pop(0)
        inst.error = flags.pop(0)
        inst.steady = flags.pop(0)
        inst.fwd = flags.pop(0)
        inst.version = flags.pop(0)
        # Call
        ntools.eq_(inst._pack_flags(), expected)

    def test(self):
        for flags, values, steady in FLAG_MAP:
            yield self._check, bytes([flags]), list(values), steady


class TestSibraExtBaseSetSize(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._set_size
    """
    def test_min(self):
        inst = SibraExtBaseTesting()
        inst._init_size = create_mock()
        # Call
        inst._set_size()
        # Tests
        inst._init_size.assert_called_once_with(0)

    def test_full(self):
        inst = SibraExtBaseTesting()
        inst._init_size = create_mock()
        inst.path_ids = ["abcd", "efgh"]
        inst.active_blocks = ["actblock0", "actblock1"]
        inst.req_block = "reqblock "
        # Call
        inst._set_size()
        # Tests
        inst._init_size.assert_called_once_with(4)


class TestSibraExtBaseReverse(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase.reverse
    """
    def test_min(self):
        inst = SibraExtBaseTesting()
        # Call
        inst.reverse()
        # Tests
        ntools.eq_(inst.fwd, False)

    def test_accepted_setup(self):
        inst = SibraExtBaseTesting()
        inst.setup = True
        inst.fwd = False
        # Call
        inst.reverse()
        # Tests
        ntools.eq_(inst.setup, False)
        ntools.eq_(inst.req_block, None)


class TestSibraExtBaseSwitchResv(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase.switch_resv
    """
    def test(self):
        inst = SibraExtBaseTesting()
        inst._set_size = create_mock()
        inst.setup = True
        inst.req_block = "req block"
        inst.total_hops = 4
        block = create_mock(["num_hops", "sofs"])
        block.num_hops = 4
        block.sofs = []
        for j in range(4):
            block.sofs.append("sof %d" % j)
        # Call
        inst.switch_resv(block)
        # Tests
        ntools.eq_(inst.setup, False)
        ntools.eq_(inst.active_blocks, [block])
        inst._set_size.assert_called_once_with()


class TestSibraExtBaseGetNextIfid(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase.get_next_ifid
    """
    def _check(self, fwd, fwd_dir, expected):
        inst = SibraExtBaseTesting()
        inst.fwd = fwd
        info = create_mock(["fwd_dir"])
        info.fwd_dir = fwd_dir
        sof = create_mock(["ingress", "egress"])
        sof.ingress = "ingress"
        sof.egress = "egress"
        block = create_mock(["info", "sofs"])
        block.info = info
        block.sofs = [sof]
        inst.active_blocks = [block]
        # Call
        ntools.eq_(inst.get_next_ifid(), expected)

    def test(self):
        for fwd, fwd_dir, expected in (
            (True, True, "egress"), (True, False, "ingress"),
            (False, True, "ingress"), (False, False, "egress"),
        ):
            yield self._check, fwd, fwd_dir, expected


class TestSibraExtBaseProcess(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase.process
    """
    def test_invalid(self):
        inst = SibraExtBaseTesting()
        inst.steady = False
        inst.setup = True
        inst._verify_sof = create_mock()
        inst._verify_sof.return_value = False
        # Call
        ntools.eq_(inst.process("state", "spkt", "from_local_as", "key"),
                   [(RouterFlag.ERROR, "Invalid packet")])
        # Tests
        inst._verify_sof.assert_called_once_with("key")

    @patch("lib.sibra.ext.ext.ProcessMeta", autospec=True)
    def _check(self, local, fwd, sof_idx, meta):
        inst = SibraExtBaseTesting()
        inst.steady = True
        inst.setup = True
        inst._update_idxes = create_mock()
        inst.fwd = fwd
        inst._process_blocks = create_mock()
        # Call
        ntools.eq_(inst.process("state", "spkt", local, "key"),
                   inst._process_blocks.return_value)
        # Tests
        meta.assert_called_once_with("state", "spkt", local, "key", fwd)
        inst._process_blocks.assert_called_once_with(meta.return_value)
        ntools.eq_(inst.sof_idx, sof_idx)
        if sof_idx != 0:
            inst._update_idxes.assert_called_once_with()

    def test(self):
        for local, fwd, sof_idx in (
            (True, True, 1), (True, False, -1), (False, None, 0),
        ):
            yield self._check, local, fwd, sof_idx


class TestSibraExtBaseProcessBlocks(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._process_blocks
    """
    def test_setup(self):
        inst = SibraExtBaseTesting()
        inst.setup = True
        inst._process_setup = create_mock()
        inst._process_setup.return_value = 1, 2, 3
        # Call
        ntools.eq_(inst._process_blocks("meta"), [1, 2, 3])
        # Tests
        inst._process_setup.assert_called_once_with("meta")

    def test_renew(self):
        inst = SibraExtBaseTesting()
        inst.req_block = True
        inst._process_renewal = create_mock()
        inst._process_renewal.return_value = 1, 2, 3
        inst._process_use = create_mock()
        inst._process_use.return_value = 4, 5, 6
        # Call
        ntools.eq_(inst._process_blocks("meta"), [1, 2, 3, 4, 5, 6])
        # Tests
        inst._process_renewal.assert_called_once_with("meta")
        inst._process_use.assert_called_once_with("meta")


class TestSibraExtBaseProcessSetup(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._process_setup
    """
    def test_rev_accepted(self):
        inst = SibraExtBaseTesting()
        inst.steady = "steady"
        inst.fwd = False
        inst.accepted = True
        inst.path_ids = [9]
        state = create_mock(["pend_confirm"])
        meta = create_mock(["state"])
        meta.state = state
        # Call
        ntools.eq_(inst._process_setup(meta), [])
        # Tests
        state.pend_confirm.assert_called_once_with(9, "steady")

    def test_rev_rejected(self):
        inst = SibraExtBaseTesting()
        inst.steady = "steady"
        inst.fwd = False
        inst.accepted = False
        inst.path_ids = [9]
        state = create_mock(["pend_remove"])
        meta = create_mock(["state"])
        meta.state = state
        # Call
        ntools.eq_(inst._process_setup(meta), [])
        # Tests
        state.pend_remove.assert_called_once_with(9, "steady")

    def test_fwd(self):
        inst = SibraExtBaseTesting()
        inst.fwd = True
        inst._process_req = create_mock()
        # Call
        ntools.eq_(inst._process_setup("meta"), [])
        # Tests
        inst._process_req.assert_called_once_with("meta")


class TestSibraExtBaseProcessRenewal(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._process_renewal
    """
    def test_rev_accepted(self):
        inst = SibraExtBaseTesting()
        inst.fwd = False
        inst.accepted = True
        inst.req_block = create_mock(["info"])
        # Call
        ntools.eq_(inst._process_renewal("meta"), [])

    def test_rev_rejected_later(self):
        inst = SibraExtBaseTesting()
        inst.steady = "steady"
        inst.fwd = False
        inst.accepted = False
        inst.path_ids = [9]
        inst.curr_hop = 4
        info = create_mock(["fail_hop", "index"])
        info.fail_hop = 5
        inst.req_block = create_mock(["info"])
        inst.req_block.info = info
        meta = create_mock(["state"])
        meta.state = create_mock(["idx_remove"])
        # Call
        ntools.eq_(inst._process_renewal(meta), [])
        # Tests
        meta.state.idx_remove.assert_called_once_with(9, info.index, "steady")

    def test_fwd(self):
        inst = SibraExtBaseTesting()
        inst.fwd = True
        inst.accepted = True
        inst._process_req = create_mock()
        # Call
        ntools.eq_(inst._process_renewal("meta"), [])
        # Tests
        inst._process_req.assert_called_once_with("meta")


class TestSibraExtBaseProcessReq(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._process_req
    """
    def _setup(self, accepted=True, bwhint=None, dir_fwd=True):
        inst = SibraExtBaseTesting()
        inst.accepted = accepted
        bwsnap = create_mock(["reverse"])
        req_info = create_mock(["bw", "index", "exp_tick"])
        req_info.bw = create_mock(["to_snap"])
        req_info.bw.to_snap.return_value = bwsnap
        inst.req_block = create_mock(["info"])
        inst.req_block.info = req_info
        meta = create_mock(["dir_fwd", "key", "spkt", "state"])
        meta.dir_fwd = dir_fwd
        inst.path_ids.append("path id 0")
        inst._req_add = create_mock()
        inst._req_add.return_value = bwhint
        inst._req_accepted = create_mock()
        inst._req_denied = create_mock()
        return inst, bwsnap, req_info, meta

    def test_fwd_accepted_to_accepted(self):
        inst, bwsnap, req_info, meta = self._setup()
        # Call
        inst._process_req(meta)
        # Tests
        ntools.assert_false(bwsnap.reverse.called)
        inst._req_add.assert_called_once_with(
            meta.state, req_info.index, bwsnap, req_info.exp_tick)
        inst._req_accepted.assert_called_once_with(True, meta.key, meta.spkt)
        ntools.assert_false(inst._req_denied.called)

    def test_rev_accepted_to_denied(self):
        inst, bwsnap, req_info, meta = self._setup(bwhint="bwhint",
                                                   dir_fwd=False)
        # Call
        inst._process_req(meta)
        # Tests
        bwsnap.reverse.assert_called_once_with()
        ntools.assert_false(inst._req_accepted.called)
        inst._req_denied.assert_called_once_with(False, "bwhint")

    def test_fwd_not_accepted(self):
        inst, bwsnap, req_info, meta = self._setup(
            accepted=False, bwhint="bwhint")
        # Call
        inst._process_req(meta)
        # Tests
        ntools.assert_false(inst._req_accepted.called)
        inst._req_denied.assert_called_once_with(True, "bwhint")


class TestSibraExtBaseProcessUse(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._process_use
    """
    def _setup(self, dir_fwd=True, use_ret=True):
        inst = SibraExtBaseTesting()
        inst.steady = "steady"
        inst.get_next_ifid = create_mock()
        inst.path_ids = [9]
        meta = create_mock(["dir_fwd", "spkt", "state"])
        meta.dir_fwd = dir_fwd
        meta.spkt = range(10)
        meta.state = create_mock(["use"])
        meta.state.use.return_value = use_ret
        block = create_mock(["info"])
        block.info = create_mock(["index"])
        inst.active_blocks = [block]
        return inst, block, meta

    @patch("lib.sibra.ext.ext.BWSnapshot", autospec=True)
    def test_dir_rev_rejected(self, bwsnap):
        inst, block, meta = self._setup(False, False)
        # Call
        ret = inst._process_use(meta)
        # Tests
        bwsnap.assert_called_once_with(80)
        bwsnap.return_value.reverse.assert_called_once_with()
        meta.state.use.assert_called_once_with(
            9, block.info.index, bwsnap.return_value, "steady")
        ntools.eq_(ret[0][0], RouterFlag.ERROR)

    @patch("lib.sibra.ext.ext.BWSnapshot", autospec=True)
    def test_dir_fwd_accepted_forward(self, bwsnap):
        inst, block, meta = self._setup()
        # Call
        ntools.eq_(inst._process_use(meta),
                   [(RouterFlag.FORWARD, inst.get_next_ifid.return_value)])
        # Tests
        ntools.assert_false(bwsnap.reverse.called)

    @patch("lib.sibra.ext.ext.BWSnapshot", autospec=True)
    def test_deliver(self, bwsnap):
        inst, block, meta = self._setup()
        inst.get_next_ifid.return_value = 0
        # Call
        ntools.eq_(inst._process_use(meta), [(RouterFlag.DELIVER,)])


class TestSibraExtBaseReqDenied(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._req_denied
    """
    def test_was_accepted(self):
        inst = SibraExtBaseTesting()
        inst._reject_req = create_mock()
        # Call
        inst._req_denied(True, "bwhint")
        # Tests
        inst._reject_req.assert_called_once_with("bwhint")

    def _check_dir_fwd(self, curr_hop, fail_hop, offer_hop):
        inst = SibraExtBaseTesting()
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

    def test_dir_fwd(self):
        for curr_hop, fail_hop, offer_hop in (
            (0, 0, 0), (1, 1, 0), (6, 3, 3),
        ):
            yield self._check_dir_fwd, curr_hop, fail_hop, offer_hop

    def test_rev(self):
        inst = SibraExtBaseTesting()
        inst.accepted = False
        inst.curr_hop = 3
        bwhint = create_mock(["reverse"])
        inst.req_block = create_mock(["add", "info"])
        inst.req_block.info = create_mock(["fail_hop"])
        inst.req_block.info.fail_hop = 0
        # Call
        inst._req_denied(False, bwhint)
        # Tests
        bwhint.reverse.assert_called_once_with()
        inst.req_block.add.assert_called_once_with(3, bwhint)


class TestSibraExtBaseRejectReq(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._reject_req
    """
    def test(self):
        inst = SibraExtBaseTesting()
        inst.curr_hop = 3
        inst.total_hops = 6
        old_req = create_mock(["info"])
        info = create_mock(["fail_hop"])
        old_req.info = info
        inst.req_block = old_req
        new_req = create_mock(["add"])
        inst.OFFER_BLOCK = create_mock(["from_values"])
        inst.OFFER_BLOCK.from_values.return_value = new_req
        inst._set_size = create_mock()
        # Call
        inst._reject_req("bwhint")
        # Tests
        ntools.assert_false(inst.accepted)
        ntools.eq_(info.fail_hop, 3)
        inst.OFFER_BLOCK.from_values.assert_called_once_with(info, 3)
        new_req.add.assert_called_once_with(3, "bwhint")
        inst._set_size.assert_called_once_with()


class TestSibraExtBaseGetPrevRaw(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._get_prev_raw
    """
    def _setup(self, fwd_dirs):
        inst = SibraExtBaseTesting()
        req_info = create_mock(["fwd_dir"])
        # Req blocks always have dir_fwd=True
        req_info.fwd_dir = True
        req_block = create_mock(["info", "num_hops", "sofs"])
        req_block.info = req_info
        req_block.num_hops = 4
        req_block.sofs = []
        for i in range(4):
            sof = create_mock(["pack"])
            sof.pack.return_value = "req sof %s" % i
            req_block.sofs.append(sof)
        inst.req_block = req_block
        for i, fwd_dir in enumerate(fwd_dirs):
            info = create_mock(["fwd_dir"])
            info.fwd_dir = fwd_dir
            block = create_mock(["info", "num_hops", "sofs"])
            block.info = info
            block.num_hops = i + 2
            block.sofs = []
            for j in range(block.num_hops):
                sof = create_mock(["pack"])
                sof.pack.return_value = "sof %s.%s" % (i, j)
                block.sofs.append(sof)
            inst.active_blocks.append(block)
        return inst

    def _check_req(self, curr_hop, expected):
        inst = self._setup([])
        inst.curr_hop = curr_hop
        # Call
        ntools.eq_(inst._get_prev_raw(req=True), expected)

    def test_req(self):
        for hop, expected in (
            (0, None), (1, "req sof 0"), (3, "req sof 2"),
        ):
            yield self._check_req, hop, expected

    def _check_active(self, fwd_dirs, b_idx, rel_s_idx, expected):
        inst = self._setup(fwd_dirs)
        inst.block_idx = b_idx
        inst.rel_sof_idx = rel_s_idx
        # Call
        ntools.eq_(inst._get_prev_raw(), expected)

    def test_active_all_fwd(self):
        for b_idx, rel_s_idx, expected in (
            (0, 0, None), (0, 1, "sof 0.0"), (2, 0, None), (2, 3, "sof 2.2"),
        ):
            yield (self._check_active, (True, True, True), b_idx, rel_s_idx,
                   expected)

    def test_active_all_rev(self):
        for b_idx, rel_s_idx, expected in (
            (0, 0, "sof 0.1"), (0, 1, None), (2, 0, "sof 2.1"), (2, 3, None),
        ):
            yield (self._check_active, (False, False, False), b_idx, rel_s_idx,
                   expected)


class TestSibraExtBaseVerifySof(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._verify_sof
    """
    def _setup(self, verified=True):
        inst = SibraExtBaseTesting()
        sof = create_mock(["calc_mac", "mac"])
        sof.mac = "abcd" if verified else "efgh"
        sof.calc_mac.return_value = "abcd"
        block = create_mock(["info", "sofs"])
        block.sofs = [sof]
        inst.active_blocks = [block]
        inst.path_ids = "path ids"
        inst._get_prev_raw = create_mock()
        return inst, block, sof

    def test_success(self):
        inst, block, sof = self._setup()
        # Call
        ntools.eq_(inst._verify_sof("key"), True)
        # Tests
        sof.calc_mac.assert_called_once_with(
            block.info, "key", "path ids", inst._get_prev_raw.return_value)

    @patch("lib.sibra.ext.ext.logging", autospec=True)
    def test_failure(self, logging):
        inst, block, curr_sof = self._setup(False)
        # Call
        ntools.eq_(inst._verify_sof("key"), False)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
