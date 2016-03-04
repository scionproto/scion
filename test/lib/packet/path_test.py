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
:mod:`lib_packet_path_test` --- lib.packet.path unit tests
==========================================================
"""
# Stdlib
from itertools import product
from unittest.mock import patch, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.path import (
    PathCombinator,
    SCIONPath,
)
from lib.packet.pcb_ext.mtu import MtuPcbExt
from test.testcommon import assert_these_calls, create_mock


class TestSCIONPathParse(object):
    """
    Unit tests for lib.packet.path.SCIONPath._parse
    """
    @patch("lib.packet.path.Raw", autospec=True)
    def test_full(self, raw):
        inst = SCIONPath()
        inst._parse_iof = create_mock()
        inst._parse_hofs = create_mock()
        inst._init_of_idxs = create_mock()
        iof_list = []
        for i in 2, 4, 6:
            iof = create_mock(["hops", "shortcut"])
            iof.hops = i
            iof.shortcut = False
            iof_list.append(iof)
        inst._parse_iof.side_effect = iof_list
        data = create_mock()
        data.side_effect = ("A IOF", "A HOFS", "B IOF", "B HOFS", "C IOF",
                            "C HOFS")
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        assert_these_calls(inst._parse_iof, [
            call(data, inst.A_IOF), call(data, inst.B_IOF),
            call(data, inst.C_IOF)
        ])
        assert_these_calls(inst._parse_hofs, [
            call(data, inst.A_HOFS, 2), call(data, inst.B_HOFS, 4),
            call(data, inst.C_HOFS, 6)
        ])
        inst._init_of_idxs.assert_called_once_with()


class TestSCIONPathParseIof(object):
    """
    Unit tests for lib.packet.path.SCIONPath._parse_iof
    """
    @patch("lib.packet.path.InfoOpaqueField", autospec=True)
    def test(self, iof):
        inst = SCIONPath()
        data = create_mock(["pop"])
        inst._ofs = create_mock(["set"])
        # Call
        ntools.eq_(inst._parse_iof(data, "label"), iof.return_value)
        # Tests
        data.pop.assert_called_once_with(iof.LEN)
        iof.assert_called_once_with(data.pop.return_value)
        inst._ofs.set.assert_called_once_with("label", [iof.return_value])


class TestSCIONPathParseHofs(object):
    """
    Unit tests for lib.packet.path.SCIONPath._parse_hofs
    """
    @patch("lib.packet.path.HopOpaqueField", autospec=True)
    def test(self, hof):
        inst = SCIONPath()
        data = create_mock(["pop"])
        inst._ofs = create_mock(["set"])
        hof.side_effect = ["hof0", "hof1", "hof2"]
        # Call
        inst._parse_hofs(data, "label", 3)
        # Tests
        assert_these_calls(data.pop, [call(hof.LEN)] * 3)
        inst._ofs.set.assert_called_once_with("label", ["hof0", "hof1", "hof2"])


class TestSCIONPathSetOfs(object):
    """
    Unit tests for lib.packet.path.SCIONPath._set_ofs
    """
    def _check(self, value, expected):
        inst = SCIONPath()
        inst._ofs = create_mock(["set"])
        # Call
        inst._set_ofs("label", value)
        # Tests
        inst._ofs.set.assert_called_once_with("label", expected)

    def test(self):
        for val, exp in (
            (None, []), ([1, 2], [1, 2]), (1, [1])
        ):
            yield self._check, val, exp


class TestSCIONPathInitOfIdxs(object):
    """
    Unit tests for lib.packet.path.SCIONPath._init_of_idxs
    """
    def test_none(self):
        inst = SCIONPath()
        inst._ofs = []
        # Call
        inst._init_of_idxs()
        # Tests
        ntools.eq_(inst._iof_idx, None)
        ntools.eq_(inst._hof_idx, None)

    def test_non_peer(self):
        inst = SCIONPath()
        inst._ofs = [1]
        iof = create_mock(["peer"])
        iof.peer = False
        inst.get_iof = create_mock()
        inst.get_iof.return_value = iof
        inst.inc_hof_idx = create_mock()
        # Call
        inst._init_of_idxs()
        # Tests
        ntools.eq_(inst._iof_idx, 0)
        ntools.eq_(inst._hof_idx, 0)
        inst.inc_hof_idx.assert_called_once_with()

    def _check_peer(self, xover, expected):
        inst = SCIONPath()
        inst._ofs = create_mock(["__len__", "get_by_idx"])
        iof = create_mock(["peer"])
        inst.get_iof = create_mock()
        inst.get_iof.return_value = iof
        hof = create_mock(["xover"])
        hof.xover = xover
        inst._ofs.get_by_idx.return_value = hof
        inst.inc_hof_idx = create_mock()
        # Call
        inst._init_of_idxs()
        # Tests
        inst._ofs.get_by_idx.assert_called_once_with(1)
        ntools.eq_(inst._iof_idx, 0)
        ntools.eq_(inst._hof_idx, expected)

    def test_peer(self):
        for xover, exp in ((False, 0), (True, 1)):
            yield self._check_peer, xover, exp


class TestSCIONPathReverse(object):
    """
    Unit tests for lib.packet.path.SCIONPath.reverse
    """
    def _setup(self, curr_label=SCIONPath.A_IOF, b_seg=False, c_seg=False):
        inst = SCIONPath()
        inst.set_of_idxs = create_mock()
        inst._iof_idx = 0
        inst._hof_idx = 1
        inst._ofs = create_mock(
            ["__len__", "count", "get_idx_by_label", "get_label_by_idx",
             "reverse_label", "reverse_up_flag", "swap"])
        inst._ofs.__len__.return_value = 10
        inst._ofs.count.side_effect = \
            lambda l: self._of_count(l, b_seg, c_seg)
        inst._ofs.get_label_by_idx.return_value = curr_label
        return inst

    def _of_count(self, label, b_seg, c_seg):
        if label == SCIONPath.B_IOF and b_seg:
            return 1
        if label == SCIONPath.C_IOF and c_seg:
            return 1
        return 0

    def test_one(self):
        inst = self._setup()
        # Call
        inst.reverse()
        # Tests
        assert_these_calls(inst._ofs.reverse_up_flag,
                           [call(l) for l in inst.IOF_LABELS])
        assert_these_calls(inst._ofs.reverse_label,
                           [call(l) for l in inst.HOF_LABELS])
        inst._ofs.get_idx_by_label.assert_called_once_with(inst.A_IOF)
        inst.set_of_idxs.assert_called_once_with(
            inst._ofs.get_idx_by_label.return_value, 9)

    def _check_two(self, curr_label, new_label):
        inst = self._setup(curr_label, b_seg=True)
        # Call
        inst.reverse()
        # Tests
        assert_these_calls(inst._ofs.swap, [
            call(inst.A_IOF, inst.B_IOF), call(inst.A_HOFS, inst.B_HOFS)])
        inst._ofs.get_idx_by_label.assert_called_once_with(new_label)

    def test_two(self):
        for curr, new in (
            (SCIONPath.A_IOF, SCIONPath.B_IOF),
            (SCIONPath.B_IOF, SCIONPath.A_IOF),
        ):
            yield self._check_two, curr, new

    def _check_three(self, curr_label, new_label):
        inst = self._setup(curr_label, b_seg=True, c_seg=True)
        # Call
        inst.reverse()
        # Tests
        assert_these_calls(inst._ofs.swap, [
            call(inst.A_IOF, inst.C_IOF), call(inst.A_HOFS, inst.C_HOFS)])
        inst._ofs.get_idx_by_label.assert_called_once_with(new_label)

    def test_three(self):
        for curr, new in (
            (SCIONPath.A_IOF, SCIONPath.C_IOF),
            (SCIONPath.B_IOF, SCIONPath.B_IOF),
            (SCIONPath.C_IOF, SCIONPath.A_IOF),
        ):
            yield self._check_three, curr, new


class TestSCIONPathGetHofVer(object):
    """
    Unit tests for lib.packet.path.SCIONPath.get_hof_ver
    """
    def _setup(self, xover=False, peer=False, shortcut=False, up_flag=True):
        inst = SCIONPath()
        inst._iof_idx = 0
        inst._hof_idx = 0
        iof = create_mock(["peer", "shortcut", "up_flag"])
        iof.peer = peer
        iof.shortcut = shortcut
        iof.up_flag = up_flag
        inst.get_iof = create_mock()
        inst.get_iof.return_value = iof
        hof = create_mock(["xover"])
        hof.xover = xover
        inst.get_hof = create_mock()
        inst.get_hof.return_value = hof
        inst._get_hof_ver_normal = create_mock()
        inst._ofs = create_mock(["get_by_idx"])
        return inst, iof, hof

    def test_normal(self):
        inst, iof, hof = self._setup()
        # Call
        ntools.eq_(inst.get_hof_ver(), inst._get_hof_ver_normal.return_value)
        # Tests
        inst._get_hof_ver_normal.assert_called_once_with(iof)

    def test_xover_shortcut(self):
        inst, iof, hof = self._setup(xover=True, shortcut=True)
        # Call
        ntools.eq_(inst.get_hof_ver(), inst._get_hof_ver_normal.return_value)
        # Tests
        inst._get_hof_ver_normal.assert_called_once_with(iof)

    def _check_xover_peer(self, ingress, up, expected):
        inst, iof, hof = self._setup(xover=True, shortcut=True, peer=True,
                                     up_flag=up)
        # Call
        ntools.eq_(inst.get_hof_ver(ingress=ingress),
                   inst._ofs.get_by_idx.return_value)
        # Tests
        inst._ofs.get_by_idx.assert_called_once_with(expected)

    def test_xover_peer(self):
        for ingress, up, exp in (
            (True, True, 2), (True, False, 1),
            (False, True, -1), (False, False, -2)
        ):
            yield self._check_xover_peer, ingress, up, exp

    def _check_xover_normal(self, ingress, up, expected):
        inst, iof, hof = self._setup(xover=True, up_flag=up)
        # Call
        ret = inst.get_hof_ver(ingress=ingress)
        # Tests
        if expected is None:
            ntools.eq_(ret, None)
        else:
            ntools.eq_(ret, inst._ofs.get_by_idx.return_value)
            inst._ofs.get_by_idx.assert_called_once_with(expected)

    def test_xover_normal(self):
        for ingress, up, exp in (
            (True, True, None), (True, False, -1),
            (False, True, +1), (False, False, None)
        ):
            yield self._check_xover_normal, ingress, up, exp


class TestSCIONPathGetHofVerNormal(object):
    """
    Unit tests for lib.packet.path.SCIONPath._get_hof_ver_normal
    """
    def _check(self, up, hof_idx, expected):
        inst = SCIONPath()
        inst._iof_idx = 0
        inst._hof_idx = hof_idx
        inst._ofs = create_mock(["get_by_idx"])
        iof = create_mock(["hops", "up_flag"])
        iof.hops = 5
        iof.up_flag = up
        # Call
        ret = inst._get_hof_ver_normal(iof)
        # Tests
        if expected is None:
            ntools.eq_(ret, None)
        else:
            ntools.eq_(ret, inst._ofs.get_by_idx.return_value)
            inst._ofs.get_by_idx.assert_called_once_with(expected)

    def test(self):
        for up, hof_idx, exp in (
            (True, 1, 2), (True, 4, 5), (True, 5, None),
            (False, 1, None), (False, 2, 1), (False, 5, 4),
        ):
            yield self._check, up, hof_idx, exp


class TestSCIONPathIncHofIdx(object):
    """
    Unit tests for lib.packet.path.SCIONPath.inc_hof_idx
    """
    def _setup(self, hof_idx):
        inst = SCIONPath()
        inst.get_iof = create_mock()
        inst.get_hof = create_mock()
        inst._iof_idx = 0
        inst._hof_idx = hof_idx
        iofs = []
        for _ in range(2):
            iof = create_mock(["hops"])
            iof.hops = 5
            iofs.append(iof)
        inst.get_iof.side_effect = iofs
        return inst, iofs

    def _mk_hof(self, verify_only):
        hof = create_mock(["verify_only"])
        hof.verify_only = verify_only
        return hof

    def test_init(self):
        inst, iofs = self._setup(0)
        hof = create_mock(["verify_only"])
        hof.verify_only = False
        inst.get_hof.return_value = hof
        # Call
        inst.inc_hof_idx()
        # Tests
        ntools.eq_(inst._hof_idx, 1)

    def test_switch(self):
        inst, iofs = self._setup(4)
        hofs = map(self._mk_hof, (True, True, False))
        inst.get_hof.side_effect = hofs
        # Call
        inst.inc_hof_idx()
        # Tests
        ntools.eq_(inst._iof_idx, 6)
        ntools.eq_(inst._hof_idx, 8)


class TestSCIONPathGetASHops(object):
    """
    Unit tests for lib.packet.path.SCIONPath.get_as_hops
    """
    def _setup(self):
        inst = SCIONPath()
        inst._ofs = create_mock(["get_by_label"])
        inst._get_as_hops = create_mock()
        inst._get_as_hops.return_value = 5
        return inst

    def _mk_iof(self, peer=False):
        iof = create_mock(['peer'])
        iof.peer = peer
        return iof

    def test_one(self):
        inst = self._setup()
        iof = self._mk_iof()
        inst._ofs.get_by_label.side_effect = [iof], None
        # Call
        ntools.eq_(inst.get_as_hops(), 5)
        # Tests
        assert_these_calls(inst._ofs.get_by_label,
                           [call(inst.A_IOF), call(inst.B_IOF)])
        inst._get_as_hops.assert_called_once_with(iof)

    def test_many(self):
        inst = self._setup()
        iof_1 = self._mk_iof()
        iof_2 = self._mk_iof()
        iof_3 = self._mk_iof()
        inst._ofs.get_by_label.side_effect = [iof_1], [iof_2], [iof_3]
        # Call
        ntools.eq_(inst.get_as_hops(), 13)
        # Tests
        assert_these_calls(inst._ofs.get_by_label,
                           [call(l) for l in inst.IOF_LABELS])
        assert_these_calls(inst._get_as_hops,
                           [call(iof_1), call(iof_2), call(iof_3)])

    def test_peer(self):
        inst = self._setup()
        iof_1 = self._mk_iof(True)
        iof_2 = self._mk_iof(True)
        inst._ofs.get_by_label.side_effect = [iof_1], [iof_2], None
        # Call
        ntools.eq_(inst.get_as_hops(), 10)
        # Tests
        assert_these_calls(inst._ofs.get_by_label,
                           [call(l) for l in inst.IOF_LABELS])
        assert_these_calls(inst._get_as_hops, [call(iof_1), call(iof_2)])


class PathCombinatorBase(object):
    def _generate_none(self):
        def _mk_seg(ases):
            seg = create_mock(["ases"])
            seg.ases = ases
            return seg

        for up, down in (
            (False, True),
            (True, False),
            (_mk_seg(False), True),
            (_mk_seg(True), _mk_seg(False)),
        ):
            yield up, down


class TestPathCombinatorBuildShortcutPaths(object):
    """
    Unit tests for lib.packet.path.PathCombinator.build_shortcut_paths
    """
    @patch("lib.packet.path.PathCombinator._build_shortcut_path",
           new_callable=create_mock)
    def test(self, build_path):
        up_segments = ['up0', 'up1']
        down_segments = ['down0', 'down1']
        build_path.side_effect = ['path0', 'path1', None, 'path1']
        ntools.eq_(
            PathCombinator.build_shortcut_paths(up_segments, down_segments),
            ["path0", "path1"])
        calls = [call(*x) for x in product(up_segments, down_segments)]
        assert_these_calls(build_path, calls)


class TestPathCombinatorBuildCorePaths(object):
    """
    Unit tests for lib.packet.path.PathCombinator.build_core_paths
    """
    @patch("lib.packet.path.PathCombinator._build_core_path",
           new_callable=create_mock)
    def test_without_core(self, build_path):
        build_path.return_value = 'path0'
        ntools.eq_(PathCombinator.build_core_paths('up', 'down', None),
                   ['path0'])
        build_path.assert_called_once_with('up', [], 'down')

    @patch("lib.packet.path.PathCombinator._build_core_path",
           new_callable=create_mock)
    def test_without_core_empty(self, build_path):
        build_path.return_value = None
        ntools.eq_(PathCombinator.build_core_paths('up', 'down', None), [])

    @patch("lib.packet.path.PathCombinator._build_core_path",
           new_callable=create_mock)
    def test_with_core(self, build_path):
        core_segments = ['core0', 'core1', 'core2', 'core3']
        build_path.side_effect = [None, 'path0', 'path1', None, 'path1']
        ntools.eq_(PathCombinator.build_core_paths('up', 'down', core_segments),
                   ['path0', 'path1'])
        calls = [call('up', [], 'down')]
        calls += [call('up', cs, 'down') for cs in core_segments]
        assert_these_calls(build_path, calls)


class TestPathCombinatorBuildShortcutPath(PathCombinatorBase):
    """
    Unit tests for lib.packet.path.PathCombinator._build_shortcut_path
    """
    def _check_none(self, up_seg, down_seg):
        ntools.assert_is_none(
            PathCombinator._build_shortcut_path(up_seg, down_seg))

    def test_none(self):
        for up, down in self._generate_none():
            yield self._check_none, up, down

    @patch("lib.packet.path.PathCombinator._get_xovr_peer",
           new_callable=create_mock)
    def test_no_xovr_peer(self, get_xovr_peer):
        up, down = create_mock(['ases']), create_mock(['ases'])
        get_xovr_peer.return_value = None, None
        # Call
        ntools.assert_is_none(PathCombinator._build_shortcut_path(up, down))
        # Tests
        get_xovr_peer.assert_called_once_with(up, down)

    @patch("lib.packet.path.PathCombinator._join_shortcuts",
           new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._get_xovr_peer",
           new_callable=create_mock)
    def _check_xovrs_peers(self, xovr, peer, is_peer, get_xovr_peer,
                           join_shortcuts):
        up, down = create_mock(['ases']), create_mock(['ases'])
        get_xovr_peer.return_value = xovr, peer
        # Call
        ntools.eq_(PathCombinator._build_shortcut_path(up, down),
                   join_shortcuts.return_value)
        # Tests
        expected = xovr
        if is_peer:
            expected = peer
        join_shortcuts.assert_called_once_with(up, down, expected, is_peer)

    def test_with_both(self):
        for xovr, peer, is_peer in (
            [(1, 2), (3, 1), True],
            [(1, 3), (3, 1), False],
            [(1, 5), (3, 1), False],
        ):
            yield self._check_xovrs_peers, xovr, peer, is_peer

    def test_with_only_xovr(self):
        yield self._check_xovrs_peers, (1, 2), None, False

    def test_with_only_peer(self):
        yield self._check_xovrs_peers, None, (1, 2), True


class TestPathCombinatorBuildCorePath(PathCombinatorBase):
    """
    Unit tests for lib.packet.path.PathCombinator._build_core_path
    """
    def _check_none(self, up_seg, down_seg):
        ntools.assert_is_none(
            PathCombinator._build_core_path(up_seg, "core", down_seg))

    def test_none(self):
        for up, down in self._generate_none():
            yield self._check_none, up, down

    @patch("lib.packet.path.PathCombinator._check_connected",
           new_callable=create_mock)
    def test_not_connected(self, check_connected):
        up, core, down = (create_mock(['ases']), create_mock(['ases']),
                          create_mock(['ases']))
        check_connected.return_value = False
        # Call
        ntools.assert_is_none(PathCombinator._build_core_path(up, core, down))
        # Tests
        check_connected.assert_called_once_with(up, core, down)

    def _mk_asm(self, mtu_base):
        asm = create_mock(["pcbm", "ext"])
        asm.pcbm = create_mock(['isd_as', 'hof'])
        asm.pcbm.hof = create_mock(['egress_if', 'ingress_if'])
        asm.ext = create_mock(['EXT_TYPE', 'mtu'])
        asm.ext.EXT_TYPE = MtuPcbExt.EXT_TYPE
        asm.ext.mtu = mtu_base * 100
        return asm

    @patch("lib.packet.path.SCIONPath", autospec=True)
    @patch("lib.packet.path.PathCombinator._copy_segment",
           new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._check_connected",
           new_callable=create_mock)
    def test_full(self, check_connected, copy_seg, scion_path):
        up = create_mock(['ases'])
        core = create_mock(['ases'])
        down = create_mock(['ases'])
        up.ases = []
        core.ases = []
        down.ases = []
        for i in range(6):
            # MTUs: 300, 400, 500, 600, 700, 800
            up.ases.append(self._mk_asm(i + 3))
            # MTUs: 500, 400, 300, 200, 100, 0 (invalid)
            core.ases.append(self._mk_asm(5 - i))
            # MTUs: 200, 300, 400, 500, 600, 700
            down.ases.append(self._mk_asm(i + 2))
        copy_seg.side_effect = [
            ("up_iof", "up_hofs", 300),
            ("core_iof", "core_hofs", 100),  # smallest valid MTU is 100
            ("down_iof", "down_hofs", 200),
        ]
        # Call
        ntools.eq_(PathCombinator._build_core_path(up, core, down),
                   scion_path.from_values.return_value)
        # Tests
        assert_these_calls(copy_seg, [
            call(up, False, True), call(core, True, True),
            call(down, True, False, up=False),
        ])
        scion_path.from_values.assert_called_once_with(
            "up_iof", "up_hofs", "core_iof", "core_hofs", "down_iof",
            "down_hofs")


class TestPathCombinatorCopySegment(object):
    """
    Unit tests for lib.packet.path.PathCombinator._copy_segment
    """
    def test_no_segment(self):
        ntools.eq_(PathCombinator._copy_segment(None, False, False, "xovrs"),
                   (None, None, None))

    @patch("lib.packet.path.PathCombinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.packet.path.copy.deepcopy", autospec=True)
    def test_copy_up(self, deepcopy, copy_hofs):
        seg = create_mock(["ases", "iof"])
        iof = create_mock(["up_flag"])
        deepcopy.return_value = iof
        hofs = []
        for _ in range(3):
            hof = create_mock(["xover"])
            hof.xover = False
            hofs.append(hof)
        copy_hofs.return_value = hofs, None
        # Call
        ntools.eq_(PathCombinator._copy_segment(seg, True, True),
                   (iof, hofs, None))
        # Tests
        deepcopy.assert_called_once_with(seg.iof)
        ntools.eq_(iof.up_flag, True)
        copy_hofs.assert_called_once_with(seg.ases, reverse=True)
        ntools.eq_(hofs[0].xover, True)
        ntools.eq_(hofs[1].xover, False)
        ntools.eq_(hofs[2].xover, True)

    @patch("lib.packet.path.PathCombinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.packet.path.copy.deepcopy", autospec=True)
    def test_copy_down(self, deepcopy, copy_hofs):
        seg = create_mock(["ases", "iof"])
        iof = create_mock(["up_flag"])
        deepcopy.return_value = iof
        copy_hofs.return_value = "hofs", None
        # Call
        ntools.eq_(PathCombinator._copy_segment(seg, False, False, up=False),
                   (iof, "hofs", None))
        # Tests
        copy_hofs.assert_called_once_with(seg.ases, reverse=False)


class TestPathCombinatorGetXovrPeer(object):
    """
    Unit tests for lib.packet.path.PathCombinator._get_xovr_peer
    """
    def _gen_segment(self, n, pms=4):
        seg = create_mock(['ases'])
        ases = []
        for i in range(n):
            asm = create_mock(['pcbm', 'pms'])
            asm.pcbm = create_mock(['isd_as'])
            asm.pms = []
            for j in range(pms):
                asm.pms.append(create_mock(['isd_as']))
            ases.append(asm)
        seg.ases = ases
        return seg

    def _setup_xovr_points(self, up, down):
        up.ases[1].pcbm.isd_as = down.ases[6].pcbm.isd_as
        up.ases[3].pcbm.isd_as = down.ases[2].pcbm.isd_as
        return (1, 6)

    def _setup_peer_points(self, up, down):
        up.ases[2].pms[1].isd_as = down.ases[5].pcbm.isd_as
        down.ases[5].pms[2].isd_as = up.ases[2].pcbm.isd_as
        up.ases[4].pms[0].isd_as = down.ases[1].pcbm.isd_as
        down.ases[1].pms[1].isd_as = up.ases[4].pcbm.isd_as
        return (2, 5)

    def test_xovr(self):
        up = self._gen_segment(5)
        down = self._gen_segment(7)
        # Setup xovr points
        expected_xovr = self._setup_xovr_points(up, down)
        # Call
        ntools.eq_(PathCombinator._get_xovr_peer(up, down),
                   (expected_xovr, None))

    def test_peer(self):
        up = self._gen_segment(5)
        down = self._gen_segment(7)
        # Setup peer points
        expected_peer = self._setup_peer_points(up, down)
        # Call
        ntools.eq_(PathCombinator._get_xovr_peer(up, down),
                   (None, expected_peer))

    def test_full(self):
        up = self._gen_segment(5)
        down = self._gen_segment(7)
        # Setup xovr points
        expected_xovr = self._setup_xovr_points(up, down)
        # Setup peer points
        expected_peer = self._setup_peer_points(up, down)
        # Call
        ntools.eq_(PathCombinator._get_xovr_peer(up, down),
                   (expected_xovr, expected_peer))


class TestPathCombinatorJoinShortcuts(object):
    """
    Unit tests for lib.packet.path.PathCombinator._join_shortcuts
    """
    @patch("lib.packet.path.SCIONPath", autospec=True)
    @patch("lib.packet.path.PathCombinator._copy_segment_shortcut",
           new_callable=create_mock)
    def test_xovr(self, cp_seg_short, scion_path):
        up_iof = create_mock(["hops", "peer", "shortcut"])
        down_iof = create_mock(["hops", "peer", "shortcut"])
        up_seg = create_mock(['ases'])
        down_seg = create_mock(['ases'])
        up_seg.ases = [create_mock(['pcbm', 'ext']) for i in range(6)]
        mtus = [i * 100 for i in range(11)]
        idx = 1
        for m in up_seg.ases:
            m.pcbm = create_mock(['isd_as', 'hof'])
            m.pcbm.hof = create_mock(['egress_if', 'ingress_if'])
            m.ext = create_mock(['EXT_TYPE', 'mtu'])
            m.ext.EXT_TYPE = MtuPcbExt.EXT_TYPE
            m.ext.mtu = mtus[idx]
            idx += 1
        down_seg.ases = [create_mock(['pcbm', 'ext']) for i in range(6)]
        idx = 10
        for m in down_seg.ases:
            m.pcbm = create_mock(['isd_as', 'hof'])
            m.pcbm.hof = create_mock(['egress_if', 'ingress_if'])
            m.ext = create_mock(['EXT_TYPE', 'mtu'])
            m.ext.EXT_TYPE = MtuPcbExt.EXT_TYPE
            m.ext.mtu = mtus[idx]
            idx -= 1
        cp_seg_short.side_effect = [
            (up_iof, ["up0", "up1"], "up_upstream_hof", 100),
            (down_iof, ["down0", "down1"], "down_upstream_hof", 400),
        ]
        # Call
        ntools.eq_(
            PathCombinator._join_shortcuts(up_seg, down_seg, (2, 5), False),
            scion_path.from_values.return_value)
        # Tests
        ntools.eq_(up_iof.shortcut, True)
        ntools.eq_(down_iof.shortcut, True)
        assert_these_calls(cp_seg_short, [
            call(up_seg, 2), call(down_seg, 5, up=False)])
        scion_path.from_values.assert_called_once_with(
            up_iof, ["up0", "up1", "up_upstream_hof"],
            down_iof, ["down_upstream_hof", "down0", "down1"])

    @patch("lib.packet.path.SCIONPath", autospec=True)
    @patch("lib.packet.path.PathCombinator._join_shortcuts_peer",
           new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._copy_segment_shortcut",
           new_callable=create_mock)
    def test_peer(self, cp_seg_short, join_peer, scion_path):
        up_seg = create_mock(['get_isd', 'ases'])
        down_seg = create_mock(['get_isd', 'ases'])
        up_seg.ases = [create_mock(['pcbm']) for i in range(6)]
        for m in up_seg.ases:
            m.pcbm = create_mock(['isd_as', 'hof'])
            m.pcbm.hof = create_mock(['egress_if', 'ingress_if'])
        down_seg.ases = [create_mock(['pcbm']) for i in range(6)]
        for m in down_seg.ases:
            m.pcbm = create_mock(['isd_as', 'hof'])
            m.pcbm.hof = create_mock(['egress_if', 'ingress_if'])
        up_iof = create_mock(["hops", "peer", "shortcut"])
        down_iof = create_mock(["hops", "peer", "shortcut"])
        cp_seg_short.side_effect = [
            (up_iof, ["up0", "up1"], "up_upstream_hof", None),
            (down_iof, ["down0", "down1"], "down_upstream_hof", None),
        ]
        up_peering_hof = create_mock(['ingress_if'])
        down_peering_hof = create_mock(['ingress_if'])
        join_peer.return_value = [up_peering_hof, down_peering_hof]
        # Call
        ntools.eq_(
            PathCombinator._join_shortcuts(up_seg, down_seg, (2, 5), True),
            scion_path.from_values.return_value)
        # Tests
        ntools.eq_(up_iof.shortcut, True)
        ntools.eq_(down_iof.shortcut, True)
        ntools.eq_(up_iof.peer, True)
        ntools.eq_(down_iof.peer, True)
        join_peer.assert_called_once_with(up_seg.ases[2], down_seg.ases[5])
        scion_path.from_values.assert_called_once_with(
            up_iof, ["up0", "up1", up_peering_hof, "up_upstream_hof"],
            down_iof, ["down_upstream_hof", down_peering_hof, "down0", "down1"])


class TestPathCombinatorCheckConnected(object):
    """
    Unit tests for lib.packet.path.PathCombinator._check_connected
    """
    def _setup(self, up_first=None, core_last=None, core_first=None,
               down_first=None):
        segs = []
        for part in ["up", "core", "down"]:
            seg = create_mock(['get_first_pcbm', 'get_last_pcbm'])
            pcbm = create_mock(['isd_as'])
            seg.get_first_pcbm.return_value = pcbm
            first = "%s_first" % part
            if locals().get(first):
                pcbm.isd_as = locals()[first]
            pcbm = create_mock(['isd_as'])
            seg.get_last_pcbm.return_value = pcbm
            last = "%s_last" % part
            if locals().get(last):
                pcbm.isd_as = locals()[last]
            segs.append(seg)
        return segs

    def test_with_core_up_discon(self):
        up, core, down = self._setup(up_first=1, core_last=2,
                                     core_first=3, down_first=3)
        ntools.assert_false(PathCombinator._check_connected(up, core, down))

    def test_with_core_down_discon(self):
        up, core, down = self._setup(up_first=1, core_last=1,
                                     core_first=2, down_first=3)
        ntools.assert_false(PathCombinator._check_connected(up, core, down))

    def test_with_core_conn(self):
        up, core, down = self._setup(up_first=1, core_last=1,
                                     core_first=2, down_first=2)
        ntools.assert_true(PathCombinator._check_connected(up, core, down))

    def test_without_core_discon(self):
        up, core, down = self._setup(up_first=1, down_first=2)
        ntools.assert_false(PathCombinator._check_connected(up, None, down))

    def test_without_core_conn(self):
        up, core, down = self._setup(up_first=1, down_first=1)
        ntools.assert_true(PathCombinator._check_connected(up, None, down))


class TestPathCombinatorCopyHofs(object):
    """
    Unit tests for lib.packet.path.PathCombinator._copy_hofs
    """
    @patch("lib.packet.path.copy.deepcopy", new_callable=create_mock)
    def test_basic(self, deepcopy):
        deepcopy.side_effect = list(range(4))
        blocks = []
        for _ in range(4):
            block = create_mock(["pcbm", "ext"])
            block.pcbm = create_mock(["hof"])
            block.ext = []
            blocks.append(block)
        # Call
        ntools.eq_(PathCombinator._copy_hofs(blocks), ([3, 2, 1, 0], None))

    @patch("lib.packet.path.copy.deepcopy", new_callable=create_mock)
    def test_no_reverse(self, deepcopy):
        deepcopy.side_effect = list(range(4))
        blocks = []
        for _ in range(4):
            block = create_mock(["pcbm", "ext"])
            block.pcbm = create_mock(["hof"])
            block.ext = []
            blocks.append(block)
        # Call
        ntools.eq_(PathCombinator._copy_hofs(blocks, reverse=False),
                   ([0, 1, 2, 3], None))


class TestPathCombinatorCopySegmentShortcut(object):
    """
    Unit tests for lib.packet.path.PathCombinator._copy_segment_shortcut
    """
    def _setup(self, deepcopy, copy_hofs):
        seg = create_mock(["iof", "ases"])
        seg.ases = []
        for _ in range(10):
            asm = create_mock(["pcbm"])
            asm.pcbm = create_mock(["hof"])
            seg.ases.append(asm)
        iof = create_mock(["hops", "up_flag"])
        iof.hops = 10
        hofs = []
        for _ in range(6):
            hofs.append(create_mock(["xover"]))
        copy_hofs.return_value = hofs, None
        upstream_hof = create_mock(["verify_only", "xover"])
        deepcopy.side_effect = [iof, upstream_hof]
        return seg, iof, hofs, upstream_hof

    @patch("lib.packet.path.PathCombinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.packet.path.copy.deepcopy", new_callable=create_mock)
    def test_up(self, deepcopy, copy_hofs):
        seg, iof, hofs, upstream_hof = self._setup(deepcopy, copy_hofs)
        # Call
        ntools.eq_(PathCombinator._copy_segment_shortcut(seg, 4),
                   (iof, hofs, upstream_hof, None))
        # Tests
        assert_these_calls(
            deepcopy, [call(seg.iof), call(seg.ases[3].pcbm.hof)])
        ntools.eq_(iof.hops, 6)
        ntools.ok_(iof.up_flag)
        copy_hofs.assert_called_once_with(seg.ases[4:], reverse=True)
        ntools.eq_(hofs[-1].xover, True)
        ntools.eq_(upstream_hof.xover, False)
        ntools.eq_(upstream_hof.verify_only, True)

    @patch("lib.packet.path.PathCombinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.packet.path.copy.deepcopy", new_callable=create_mock)
    def test_down(self, deepcopy, copy_hofs):
        seg, iof, hofs, upstream_hof = self._setup(deepcopy, copy_hofs)
        # Call
        ntools.eq_(PathCombinator._copy_segment_shortcut(seg, 7, up=False),
                   (iof, hofs, upstream_hof, None))
        # Tests
        ntools.assert_false(iof.up_flag)
        copy_hofs.assert_called_once_with(seg.ases[7:], reverse=False)
        ntools.eq_(hofs[0].xover, True)
        ntools.eq_(upstream_hof.verify_only, True)


class TestPathCombinatorJoinShortcutsPeer(object):
    """
    Unit tests for lib.packet.path.PathCombinator._join_shortcuts_peer
    """
    def test(self):
        up_as = create_mock(['pms', 'pcbm'])
        up_as.pcbm = create_mock(['isd_as'])
        up_as.pcbm.isd_as = "1-1"
        down_as = create_mock(['pms', 'pcbm'])
        down_as.pcbm = create_mock(['isd_as'])
        down_as.pcbm.isd_as = "1-2"
        up_as.pms = [create_mock(['isd_as', 'hof']) for i in range(2)]
        down_as.pms = [create_mock(['isd_as', 'hof']) for i in range(3)]
        up_as.pms[1].isd_as = "1-2"
        up_as.pms[1].hof = 'up_hof1'
        down_as.pms[0].isd_as = "1-1"
        down_as.pms[0].hof = 'down_hof0'
        ntools.eq_(PathCombinator._join_shortcuts_peer(up_as, down_as),
                   ("up_hof1", "down_hof0"))


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
