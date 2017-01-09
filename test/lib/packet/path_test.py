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
from test.testcommon import assert_these_calls, create_mock, create_mock_full


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
    def test_empty(self):
        inst = SCIONPath()
        inst._ofs = []
        # Call
        inst._init_of_idxs()
        # Tests
        ntools.eq_(inst._iof_idx, 0)
        ntools.eq_(inst._hof_idx, 0)

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
    def _mk_seg(self, asms):
        seg = create_mock(["p"])
        seg.p = create_mock(["asms"])
        seg.p.asms = asms
        return seg

    def _generate_none(self):

        for up, down in (
            (False, True),
            (True, False),
            (self._mk_seg(False), True),
            (self._mk_seg(True), self._mk_seg(False)),
        ):
            yield up, down


class TestPathCombinatorBuildShortcutPaths(object):
    """
    Unit tests for lib.packet.path.PathCombinator.build_shortcut_paths
    """
    @patch("lib.packet.path.PathCombinator._build_shortcuts",
           new_callable=create_mock)
    def test(self, build_path):
        up_segments = ['up0', 'up1']
        down_segments = ['down0', 'down1']
        build_path.side_effect = [['path0'], ['path1'], [], ['path1']]
        ntools.eq_(
            PathCombinator.build_shortcut_paths(up_segments, down_segments),
            ["path0", "path1"])
        calls = [call(*x) for x in product(up_segments, down_segments)]
        assert_these_calls(build_path, calls)


class TestPathCombinatorBuildShortcuts(PathCombinatorBase):
    """
    Unit tests for lib.packet.path.PathCombinator._build_shortcuts
    """
    def _check_none(self, up_seg, down_seg):
        ntools.eq_(PathCombinator._build_shortcuts(up_seg, down_seg), [])

    def test_none(self):
        for up, down in self._generate_none():
            yield self._check_none, up, down

    @patch("lib.packet.path.PathCombinator._get_xovr_peer",
           new_callable=create_mock)
    def test_no_xovr_peer(self, get_xovr_peer):
        up = self._mk_seg(True)
        down = self._mk_seg(True)
        get_xovr_peer.return_value = None, None
        # Call
        ntools.eq_(PathCombinator._build_shortcuts(up, down), [])
        # Tests
        get_xovr_peer.assert_called_once_with(up, down)

    @patch("lib.packet.path.PathCombinator._join_xovr",
           new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._join_peer",
           new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._get_xovr_peer",
           new_callable=create_mock)
    def _check_xovrs_peers(self, xovr, peer, is_peer, get_xovr_peer,
                           join_peer, join_xovr):
        up = self._mk_seg(True)
        down = self._mk_seg(True)
        get_xovr_peer.return_value = xovr, peer
        # Call
        if is_peer:
            ntools.eq_(PathCombinator._build_shortcuts(up, down),
                       join_peer.return_value)
        else:
            ntools.eq_(PathCombinator._build_shortcuts(up, down),
                       join_xovr.return_value)
        # Tests
        if is_peer:
            join_peer.assert_called_once_with(up, down, peer)
        else:
            join_xovr.assert_called_once_with(up, down, xovr)

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


class TestPathCombinatorCopySegment(object):
    """
    Unit tests for lib.packet.path.PathCombinator._copy_segment
    """
    def test_no_segment(self):
        ntools.eq_(PathCombinator._copy_segment(None, False, False, "xovrs"),
                   (None, None, float("inf")))

    @patch("lib.packet.path.PathCombinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.packet.path.copy.deepcopy", autospec=True)
    def test_copy_up(self, deepcopy, copy_hofs):
        seg = create_mock(["iter_asms", "info"])
        info = create_mock(["up_flag"])
        deepcopy.return_value = info
        hofs = []
        for _ in range(3):
            hof = create_mock(["xover"])
            hof.xover = False
            hofs.append(hof)
        copy_hofs.return_value = hofs, None
        # Call
        ntools.eq_(PathCombinator._copy_segment(seg, True, True),
                   (info, hofs, None))
        # Tests
        deepcopy.assert_called_once_with(seg.info)
        ntools.eq_(info.up_flag, True)
        copy_hofs.assert_called_once_with(seg.iter_asms.return_value,
                                          reverse=True)
        ntools.eq_(hofs[0].xover, True)
        ntools.eq_(hofs[1].xover, False)
        ntools.eq_(hofs[2].xover, True)

    @patch("lib.packet.path.PathCombinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.packet.path.copy.deepcopy", autospec=True)
    def test_copy_down(self, deepcopy, copy_hofs):
        seg = create_mock(["iter_asms", "info"])
        info = create_mock(["up_flag"])
        deepcopy.return_value = info
        copy_hofs.return_value = "hofs", None
        # Call
        ntools.eq_(PathCombinator._copy_segment(seg, False, False, up=False),
                   (info, "hofs", None))
        # Tests
        copy_hofs.assert_called_once_with(seg.iter_asms.return_value,
                                          reverse=False)


class TestPathCombinatorGetXovrPeer(object):
    """
    Unit tests for lib.packet.path.PathCombinator._get_xovr_peer
    """
    def test_none(self):
        seg = create_mock_full({"iter_asms()": [],
                                "get_rev_map()": {}})
        # Call
        ntools.eq_(PathCombinator._get_xovr_peer(seg, seg), (None, None))

    @patch("lib.packet.path.PathCombinator._find_peer_hfs",
           new_callable=create_mock)
    def test_xovr(self, find):
        up_asms = [
            create_mock_full({"isd_as()": "1-1"}),
            create_mock_full({"isd_as()": "1-2"}),
            create_mock_full({"isd_as()": "1-3"}),
        ]
        up_seg = create_mock_full({"iter_asms()": up_asms,
                                   "get_rev_map()": {}})
        down_asms = [
            create_mock_full({"isd_as()": "1-1"}),
            create_mock_full({"isd_as()": "1-2"}),
            create_mock_full({"isd_as()": "1-4"}),
        ]
        down_seg = create_mock_full({"iter_asms()": down_asms,
                                     "get_rev_map()": {}})
        find.return_value = False
        # Call
        ntools.eq_(PathCombinator._get_xovr_peer(up_seg, down_seg),
                   ((2, 2), None))

    @patch("lib.packet.path.PathCombinator._find_peer_hfs",
           new_callable=create_mock)
    def test_peer(self, find):
        up_asms = [
            create_mock_full({"isd_as()": "1-1"}),  # peers with 1-10
            create_mock_full({"isd_as()": "1-2"}),  # peers with 1-12
            create_mock_full({"isd_as()": "1-3"}),
        ]
        up_seg = create_mock_full({"iter_asms()": up_asms,
                                   "get_rev_map()": {}})
        down_asms = [
            create_mock_full({"isd_as()": "1-10"}),  # peers with 1-1
            create_mock_full({"isd_as()": "1-11"}),
            create_mock_full({"isd_as()": "1-12"}),  # peers with 1-2
        ]
        down_seg = create_mock_full({"iter_asms()": down_asms,
                                     "get_rev_map()": {}})

        def matching_peers(a, b, c, d):
            return (a == up_asms[0] and b == down_asms[0]) or (
                a == up_asms[1] and b == down_asms[2])
        find.side_effect = matching_peers
        # Call
        ntools.eq_(PathCombinator._get_xovr_peer(up_seg, down_seg),
                   (None, (2, 3)))


class PathCombinatorJoinShortcutsBase(object):
    def _setup(self, path_args, copy_segment):
        up_segment = create_mock(["asm", "get_rev_map"])
        up_segment.asm = create_mock()
        up_segment.get_rev_map.return_value = {}
        down_segment = create_mock(["asm", "get_rev_map"])
        down_segment.asm = create_mock()
        down_segment.get_rev_map.return_value = {}
        point = (1, 2)
        up_iof = create_mock(["shortcut", "peer"])
        down_iof = create_mock(["shortcut", "peer"])
        copy_segment.side_effect = [(up_iof, ["A", "B"], "up hof", 1500),
                                    (down_iof, ["C"], "down hof", 1400)]
        path_args.return_value = ()
        return up_segment, down_segment, point


class TestPathCombinatorJoinCrossover(PathCombinatorJoinShortcutsBase):
    """
    Unit test for lib.packet.path.PathCombinator._join_xovr
    """
    @patch("lib.packet.path.PathCombinator._copy_segment_shortcut",
           new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._shortcut_path_args",
           new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._build_interface_list",
           new_callable=create_mock)
    def test_xovr(self, build_list, path_args, copy_segment):
        up_segment, down_segment, point = self._setup(path_args, copy_segment)
        path = SCIONPath.from_values()
        path.mtu = 1400
        ntools.eq_(
            PathCombinator._join_xovr(up_segment, down_segment, point)[0], path)
        copy_segment.assert_any_call(up_segment, 1)
        copy_segment.assert_any_call(down_segment, 2, up=False)
        ntools.eq_(build_list.call_count, 1)


class TestPathCombinatorJoinPeer(PathCombinatorJoinShortcutsBase):
    """
    Unit test for lib.packet.path.PathCombinator._join_xovr
    """
    @patch("lib.packet.path.PathCombinator._copy_segment_shortcut",
           new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._shortcut_path_args",
           new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._build_interface_list",
           new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._find_peer_hfs",
           new_callable=create_mock)
    def test_peer(self, find_peers, build_list, path_args, copy_segment):
        up_segment, down_segment, point = self._setup(path_args, copy_segment)
        find_peers.return_value = [("uph1", "dph1", 1500),
                                   ("uph2", "dph2", 1500)]
        path = SCIONPath.from_values()
        path.mtu = 1400
        ntools.eq_(
            PathCombinator._join_peer(up_segment, down_segment, point)[0], path)
        copy_segment.assert_any_call(up_segment, 1)
        copy_segment.assert_any_call(down_segment, 2, up=False)
        ntools.eq_(build_list.call_count, 2)


class TestPathCombinatorShortcutPathArgs(object):
    """
    Unit test for lib.packet.path.PathCombinator._shortcut_path_args
    """
    def test(self):
        up_iof = create_mock(["hops"])
        up_hofs = ["up hof 1", "up hof 2", "up hof 3"]
        down_iof = create_mock(["hops"])
        down_hofs = ["down hof"]
        ret = PathCombinator._shortcut_path_args(up_iof, up_hofs,
                                                 down_iof, down_hofs)
        ntools.eq_(ret, [up_iof, up_hofs])
        ntools.eq_(up_iof.hops, 3)


class TestPathCombinatorBuildInterfaceList(object):
    """
    Unit tests for lib.packet.path.PathCombinator._build_interface_list
    """
    @patch("lib.packet.path.PathCombinator._add_interfaces",
           new_callable=create_mock)
    def _check_xovr_peers(self, peers, add_ifs):
        path = create_mock(["interfaces"])
        path.interfaces = []
        up_asm = create_mock_full({"isd_as()": 11})
        up_seg = create_mock_full({"iter_asms()": ["A", "B"], "asm()": up_asm})
        up_idx = 1
        down_asm = create_mock_full({"isd_as()": 12})
        down_seg = create_mock_full({"iter_asms()": ["C", "D"],
                                     "asm()": down_asm})
        down_idx = 2

        PathCombinator._build_interface_list(path, up_seg, up_idx,
                                             down_seg, down_idx, peers)
        assert_these_calls(
            add_ifs, [call(path, ["B", "A"]), call(path, ["C", "D"], up=False)])
        if peers:
            up_hof, down_hof = peers
            ntools.eq_(path.interfaces, [(11, up_hof.ingress_if),
                                         (12, down_hof.ingress_if)])

    def test_xovr(self):
        yield self._check_xovr_peers, None

    def test_peers(self):
        up_hof = create_mock(["ingress_if"])
        up_hof.ingress_if = 3
        down_hof = create_mock(["ingress_if"])
        down_hof.ingress_if = 4
        yield self._check_xovr_peers, (up_hof, down_hof)


class TestPathCombinatorAddInterfaces(object):
    """
    Unit tests for lib.packet.path.PathCombinator._add_interfaces
    """
    def _check_up_down(self, up):
        asms = []
        ifid = 0
        for i in range(1, 4):
            if up:
                hof = create_mock_full({"egress_if": ifid,
                                        "ingress_if": ifid + 1})
                if i == 3:
                    hof.ingress_if = 0
            else:
                hof = create_mock_full({"egress_if": ifid + 1,
                                        "ingress_if": ifid})
                if i == 3:
                    hof.egress_if = 0
            ifid += 2
            pcbm = create_mock_full({"hof()": hof})
            asms.append(create_mock_full({"isd_as()": i, "pcbm()": pcbm}))
        path = create_mock(["interfaces"])
        path.interfaces = []
        PathCombinator._add_interfaces(path, asms, up)
        ntools.eq_(path.interfaces, [(1, 1), (2, 2), (2, 3), (3, 4)])

    def test_up(self):
        yield self._check_up_down, True

    def test_down(self):
        yield self._check_up_down, False


class TestPathCombinatorCheckConnected(object):
    """
    Unit tests for lib.packet.path.PathCombinator._check_connected
    """
    def _setup(self, up_first, core_last, core_first, down_first):
        up = create_mock(['first_ia'])
        up.first_ia.return_value = up_first
        yield up
        core = create_mock(['first_ia', 'last_ia'])
        core.first_ia.return_value = core_first
        core.last_ia.return_value = core_last
        yield core
        down = create_mock(['first_ia'])
        down.first_ia.return_value = down_first
        yield down

    def test_with_core_up_discon(self):
        up, core, down = self._setup(1, 2, 3, 3)
        ntools.assert_false(PathCombinator._check_connected(up, core, down))

    def test_with_core_down_discon(self):
        up, core, down = self._setup(1, 1, 2, 3)
        ntools.assert_false(PathCombinator._check_connected(up, core, down))

    def test_with_core_conn(self):
        up, core, down = self._setup(1, 1, 2, 2)
        ntools.assert_true(PathCombinator._check_connected(up, core, down))

    def test_without_core_discon(self):
        up, core, down = self._setup(1, 0, 0, 2)
        ntools.assert_false(PathCombinator._check_connected(up, None, down))

    def test_without_core_conn(self):
        up, core, down = self._setup(1, 0, 0, 1)
        ntools.assert_true(PathCombinator._check_connected(up, None, down))


class TestPathCombinatorCopyHofs(object):
    """
    Unit tests for lib.packet.path.PathCombinator._copy_hofs
    """
    def test_full(self):
        asms = []
        for i in range(4):
            pcbm = create_mock(["hof", "p"])
            pcbm.hof.return_value = i
            pcbm.p = create_mock(["inMTU"])
            pcbm.p.inMTU = (i + 1) * 2
            asm = create_mock(["pcbm", "p"])
            asm.pcbm.return_value = pcbm
            asm.p = create_mock(["mtu"])
            asm.p.mtu = (i + 1) * 0.5
            asms.append(asm)
        # Call
        ntools.eq_(PathCombinator._copy_hofs(asms), ([3, 2, 1, 0], 0.5))


class TestPathCombinatorCopySegmentShortcut(object):
    """
    Unit tests for lib.packet.path.PathCombinator._copy_segment_shortcut
    """
    def _setup(self, deepcopy, copy_hofs):
        info = create_mock(["hops", "up_flag"])
        info.hops = 10
        upstream_hof = create_mock(["verify_only", "xover"])
        pcbm = create_mock(["hof"])
        pcbm.hof.return_value = upstream_hof
        asm = create_mock(["pcbm"])
        asm.pcbm.return_value = pcbm
        seg = create_mock(["asm", "info", "iter_asms"])
        seg.asm.return_value = asm
        hofs = []
        for _ in range(6):
            hofs.append(create_mock(["xover"]))
        copy_hofs.return_value = hofs, "mtu"
        deepcopy.side_effect = info, upstream_hof
        return seg, info, hofs, upstream_hof

    @patch("lib.packet.path.PathCombinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.packet.path.copy.deepcopy", new_callable=create_mock)
    def test_up(self, deepcopy, copy_hofs):
        seg, info, hofs, upstream_hof = self._setup(deepcopy, copy_hofs)
        # Call
        ntools.eq_(PathCombinator._copy_segment_shortcut(seg, 4),
                   (info, hofs, upstream_hof, "mtu"))
        # Tests
        deepcopy.assert_called_once_with(seg.info)
        ntools.eq_(info.hops, 6)
        ntools.ok_(info.up_flag)
        copy_hofs.assert_called_once_with(seg.iter_asms.return_value,
                                          reverse=True)
        ntools.eq_(hofs[-1].xover, True)
        ntools.eq_(upstream_hof.xover, False)
        ntools.eq_(upstream_hof.verify_only, True)

    @patch("lib.packet.path.PathCombinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.packet.path.copy.deepcopy", new_callable=create_mock)
    def test_down(self, deepcopy, copy_hofs):
        seg, info, hofs, upstream_hof = self._setup(deepcopy, copy_hofs)
        # Call
        ntools.eq_(PathCombinator._copy_segment_shortcut(seg, 7, up=False),
                   (info, hofs, upstream_hof, "mtu"))
        # Tests
        ntools.assert_false(info.up_flag)
        copy_hofs.assert_called_once_with(seg.iter_asms.return_value,
                                          reverse=False)
        ntools.eq_(hofs[0].xover, True)
        ntools.eq_(upstream_hof.verify_only, True)


class TestPathCombinatorFindPeerHfs(object):
    """
    Unit tests for lib.packet.path.PathCombinator._find_peer_hfs
    """
    def _mk_pcbms(self):
        up_pcbms = [
            self._mk_pcbm("2-1", 1, 1, 500),
            self._mk_pcbm("2-1", 2, 2, 600),  # Not reciprocated
            self._mk_pcbm("2-1", 3, 3, 700),
        ]
        down_pcbms = [
            # Local 2-1
            self._mk_pcbm("1-1", 1, 1, 500),
            self._mk_pcbm("1-1", 3, 3, 700),
        ]
        return up_pcbms, down_pcbms

    def _mk_pcbm(self, inIA, inIF, hof_ingress, mtu):
        hof = create_mock_full({"ingress_if": hof_ingress})
        p = create_mock_full({"inIF": inIF, "inMTU": mtu})
        return create_mock_full({"inIA()": inIA, "p": p, "hof()": hof})

    def test(self):
        up_pcbms, down_pcbms = self._mk_pcbms()
        p = create_mock_full({"hashTreeRoot": b"1234"})
        up_asm = create_mock_full({"isd_as()": "1-1", "iter_pcbms()": up_pcbms,
                                   "p": p})
        down_asm = create_mock_full({"isd_as()": "2-1",
                                     "iter_pcbms()": down_pcbms,
                                     "p": p})
        # Call
        ntools.eq_(PathCombinator._find_peer_hfs(up_asm, down_asm, {}, {}), [
            (up_pcbms[0].hof(), down_pcbms[0].hof(), 500),
            (up_pcbms[2].hof(), down_pcbms[1].hof(), 700),
        ])

    @patch("lib.packet.path.PathCombinator._skip_peer",
           new_callable=create_mock)
    def test_with_revocation(self, skip_peer):
        up_pcbms, down_pcbms = self._mk_pcbms()
        p = create_mock_full({"hashTreeRoot": b"1234"})
        up_asm = create_mock_full({"isd_as()": "1-1",
                                   "iter_pcbms()": up_pcbms,
                                   "p": p})
        down_asm = create_mock_full({"isd_as()": "2-1",
                                     "iter_pcbms()": down_pcbms,
                                     "p": p})
        up_peer_rev = create_mock()
        down_peer_rev = create_mock()
        up_rev_map = {("1-1", 3): up_peer_rev}
        down_rev_map = {("2-1", 3): down_peer_rev}

        def skip_peer_side_effect(rev, ht_root):
            if rev in [up_peer_rev, down_peer_rev] and ht_root == b"1234":
                return True
            return False
        skip_peer.side_effect = skip_peer_side_effect

        # Call
        peers = PathCombinator._find_peer_hfs(up_asm, down_asm, up_rev_map,
                                              down_rev_map)
        # Tests
        ntools.eq_(peers, [(up_pcbms[0].hof(), down_pcbms[0].hof(), 500)])
        skip_peer.assert_has_calls(
            [call(None, b"1234"), call(up_peer_rev, b"1234")], any_order=True)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
