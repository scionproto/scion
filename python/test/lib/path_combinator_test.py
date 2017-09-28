# Copyright 2017 ETH Zurich
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
:mod:`lib_path_combinator_test` --- lib.path_combinator test
============================================================
"""
# Stdlib
from itertools import product
from unittest.mock import patch, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib import path_combinator
from lib.packet.path import SCIONPath
from lib.sciond_api.path_meta import FwdPathMeta, PathInterface
from test.testcommon import assert_these_calls, create_mock, create_mock_full


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
    Unit tests for lib.path_combinator.build_shortcut_paths
    """
    @patch("lib.path_combinator._build_shortcuts",
           new_callable=create_mock)
    def test(self, build_path):
        up_segments = ['up0', 'up1']
        down_segments = ['down0', 'down1']
        build_path.side_effect = [['path0'], ['path1'], [], ['path1']]
        peer_revs = create_mock()
        ntools.eq_(
            path_combinator.build_shortcut_paths(
                up_segments, down_segments, peer_revs),
            ["path0", "path1"])
        calls = [call(*x, peer_revs)
                 for x in product(up_segments, down_segments)]
        assert_these_calls(build_path, calls)


class TestPathCombinatorBuildShortcuts(PathCombinatorBase):
    """
    Unit tests for lib.path_combinator._build_shortcuts
    """
    def _check_none(self, up_seg, down_seg):
        peer_revs = create_mock()
        ntools.eq_(
            path_combinator._build_shortcuts(up_seg, down_seg, peer_revs), [])

    def test_none(self):
        for up, down in self._generate_none():
            yield self._check_none, up, down

    @patch("lib.path_combinator._get_xovr_peer",
           new_callable=create_mock)
    def test_no_xovr_peer(self, get_xovr_peer):
        up = self._mk_seg(True)
        down = self._mk_seg(True)
        get_xovr_peer.return_value = None, None
        peer_revs = create_mock()
        # Call
        ntools.eq_(path_combinator._build_shortcuts(up, down, peer_revs), [])
        # Tests
        get_xovr_peer.assert_called_once_with(up, down, peer_revs)

    @patch("lib.path_combinator._join_xovr",
           new_callable=create_mock)
    @patch("lib.path_combinator._join_peer",
           new_callable=create_mock)
    @patch("lib.path_combinator._get_xovr_peer",
           new_callable=create_mock)
    def _check_xovrs_peers(self, xovr, peer, is_peer, get_xovr_peer,
                           join_peer, join_xovr):
        up = self._mk_seg(True)
        down = self._mk_seg(True)
        get_xovr_peer.return_value = xovr, peer
        peer_revs = create_mock()
        # Call
        if is_peer:
            ntools.eq_(path_combinator._build_shortcuts(up, down, peer_revs),
                       join_peer.return_value)
        else:
            ntools.eq_(path_combinator._build_shortcuts(up, down, peer_revs),
                       join_xovr.return_value)
        # Tests
        if is_peer:
            join_peer.assert_called_once_with(up, down, peer, peer_revs)
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
    Unit tests for lib.path_combinator._copy_segment
    """
    def test_no_segment(self):
        ntools.eq_(path_combinator._copy_segment(None, False, False, "xovrs"),
                   (None, None, float("inf")))

    @patch("lib.path_combinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.path_combinator.copy.deepcopy", autospec=True)
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
        ntools.eq_(path_combinator._copy_segment(seg, True, True),
                   (info, hofs, None))
        # Tests
        deepcopy.assert_called_once_with(seg.info)
        ntools.eq_(info.up_flag, True)
        copy_hofs.assert_called_once_with(seg.iter_asms.return_value,
                                          reverse=True)
        ntools.eq_(hofs[0].xover, True)
        ntools.eq_(hofs[1].xover, False)
        ntools.eq_(hofs[2].xover, True)

    @patch("lib.path_combinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.path_combinator.copy.deepcopy", autospec=True)
    def test_copy_down(self, deepcopy, copy_hofs):
        seg = create_mock(["iter_asms", "info"])
        info = create_mock(["up_flag"])
        deepcopy.return_value = info
        copy_hofs.return_value = "hofs", None
        # Call
        ntools.eq_(path_combinator._copy_segment(seg, False, False, up=False),
                   (info, "hofs", None))
        # Tests
        copy_hofs.assert_called_once_with(seg.iter_asms.return_value,
                                          reverse=False)


class TestPathCombinatorGetXovrPeer(object):
    """
    Unit tests for lib.path_combinator._get_xovr_peer
    """
    def test_none(self):
        seg = create_mock_full({"iter_asms()": []})
        peer_revs = create_mock()
        # Call
        ntools.eq_(path_combinator._get_xovr_peer(seg, seg, peer_revs),
                   (None, None))

    @patch("lib.path_combinator._find_peer_hfs",
           new_callable=create_mock)
    def test_xovr(self, find):
        up_asms = [
            create_mock_full({"isd_as()": "1-1"}),
            create_mock_full({"isd_as()": "1-2"}),
            create_mock_full({"isd_as()": "1-3"}),
        ]
        up_seg = create_mock_full({"iter_asms()": up_asms})
        down_asms = [
            create_mock_full({"isd_as()": "1-1"}),
            create_mock_full({"isd_as()": "1-2"}),
            create_mock_full({"isd_as()": "1-4"}),
        ]
        down_seg = create_mock_full({"iter_asms()": down_asms})
        find.return_value = False
        peer_revs = create_mock()
        # Call
        ntools.eq_(path_combinator._get_xovr_peer(up_seg, down_seg, peer_revs),
                   ((2, 2), None))

    @patch("lib.path_combinator._find_peer_hfs",
           new_callable=create_mock)
    def test_peer(self, find):
        up_asms = [
            create_mock_full({"isd_as()": "1-1"}),  # peers with 1-10
            create_mock_full({"isd_as()": "1-2"}),  # peers with 1-12
            create_mock_full({"isd_as()": "1-3"}),
        ]
        up_seg = create_mock_full({"iter_asms()": up_asms})
        down_asms = [
            create_mock_full({"isd_as()": "1-10"}),  # peers with 1-1
            create_mock_full({"isd_as()": "1-11"}),
            create_mock_full({"isd_as()": "1-12"}),  # peers with 1-2
        ]
        down_seg = create_mock_full({"iter_asms()": down_asms})
        peer_revs = create_mock()

        def matching_peers(a, b, c):
            return (a == up_asms[0] and b == down_asms[0]) or (
                a == up_asms[1] and b == down_asms[2])
        find.side_effect = matching_peers
        # Call
        ntools.eq_(path_combinator._get_xovr_peer(up_seg, down_seg, peer_revs),
                   (None, (2, 3)))


class PathCombinatorJoinShortcutsBase(object):
    def _setup(self, path_args, copy_segment):
        up_segment = create_mock(["asm"])
        up_segment.asm = create_mock()
        down_segment = create_mock(["asm"])
        down_segment.asm = create_mock()
        point = (1, 2)
        up_iof = create_mock(["shortcut", "peer"])
        down_iof = create_mock(["shortcut", "peer"])
        copy_segment.side_effect = [(up_iof, ["A", "B"], "up hof", 1500),
                                    (down_iof, ["C"], "down hof", 1400)]
        path_args.return_value = ()
        return up_segment, down_segment, point


class TestPathCombinatorJoinCrossover(PathCombinatorJoinShortcutsBase):
    """
    Unit test for lib.path_combinator._join_xovr
    """
    @patch("lib.path_combinator._copy_segment_shortcut",
           new_callable=create_mock)
    @patch("lib.path_combinator._shortcut_path_args",
           new_callable=create_mock)
    @patch("lib.path_combinator._build_shortcut_interface_list",
           new_callable=create_mock)
    def test_xovr(self, build_list, path_args, copy_segment):
        up_segment, down_segment, point = self._setup(path_args, copy_segment)
        path_meta = FwdPathMeta.from_values(SCIONPath(), [], 0)
        ntools.eq_(
            path_combinator._join_xovr(up_segment, down_segment, point)[0],
            path_meta)
        copy_segment.assert_any_call(up_segment, 1)
        copy_segment.assert_any_call(down_segment, 2, up=False)
        ntools.eq_(build_list.call_count, 1)


class TestPathCombinatorJoinPeer(PathCombinatorJoinShortcutsBase):
    """
    Unit test for lib.path_combinator._join_xovr
    """
    @patch("lib.path_combinator._copy_segment_shortcut",
           new_callable=create_mock)
    @patch("lib.path_combinator._shortcut_path_args",
           new_callable=create_mock)
    @patch("lib.path_combinator._build_shortcut_interface_list",
           new_callable=create_mock)
    @patch("lib.path_combinator._find_peer_hfs",
           new_callable=create_mock)
    def test_peer(self, find_peers, build_list, path_args, copy_segment):
        up_segment, down_segment, point = self._setup(path_args, copy_segment)
        find_peers.return_value = [("uph1", "dph1", 1500),
                                   ("uph2", "dph2", 1500)]
        peer_revs = create_mock()
        path_meta = FwdPathMeta.from_values(SCIONPath(), [], 0)
        ntools.eq_(path_combinator._join_peer(
            up_segment, down_segment, point, peer_revs)[0], path_meta)
        copy_segment.assert_any_call(up_segment, 1)
        copy_segment.assert_any_call(down_segment, 2, up=False)
        ntools.eq_(build_list.call_count, 2)


class TestPathCombinatorShortcutPathArgs(object):
    """
    Unit test for lib.path_combinator._shortcut_path_args
    """
    def test(self):
        up_iof = create_mock(["hops"])
        up_hofs = ["up hof 1", "up hof 2", "up hof 3"]
        down_iof = create_mock(["hops"])
        down_hofs = ["down hof"]
        ret = path_combinator._shortcut_path_args(up_iof, up_hofs,
                                                  down_iof, down_hofs)
        ntools.eq_(ret, [up_iof, up_hofs])
        ntools.eq_(up_iof.hops, 3)


class TestPathCombinatorBuildShortcutInterfaceList(object):
    """
    Unit tests for
    lib.path_combinator._build_shortcut_interface_list
    """
    @patch("lib.path_combinator._build_interface_list",
           new_callable=create_mock)
    def _check_xovr_peers(self, peers, build_if_list):
        up_asm = create_mock_full({"isd_as()": 11})
        up_seg = create_mock_full({"iter_asms()": ["A", "B"], "asm()": up_asm})
        up_idx = 1
        down_asm = create_mock_full({"isd_as()": 12})
        down_seg = create_mock_full({"iter_asms()": ["C", "D"],
                                     "asm()": down_asm})
        down_idx = 2
        build_if_list.side_effect = [[], []]

        if_list = path_combinator._build_shortcut_interface_list(
            up_seg, up_idx, down_seg, down_idx, peers)
        assert_these_calls(build_if_list, [call(["B", "A"]),
                           call(["C", "D"], up=False)])
        if peers:
            up_hof, down_hof = peers
            ntools.eq_(
                if_list, [PathInterface.from_values(11, up_hof.ingress_if),
                          PathInterface.from_values(12, down_hof.ingress_if)])

    def test_xovr(self):
        yield self._check_xovr_peers, None

    def test_peers(self):
        up_hof = create_mock(["ingress_if"])
        up_hof.ingress_if = 3
        down_hof = create_mock(["ingress_if"])
        down_hof.ingress_if = 4
        yield self._check_xovr_peers, (up_hof, down_hof)


class TestPathCombinatorBuildInterfaceList(object):
    """
    Unit tests for lib.path_combinator._build_interface_list
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
        if_list = path_combinator._build_interface_list(asms, up)
        ntools.eq_(if_list, [PathInterface.from_values(1, 1),
                             PathInterface.from_values(2, 2),
                             PathInterface.from_values(2, 3),
                             PathInterface.from_values(3, 4)])

    def test_up(self):
        yield self._check_up_down, True

    def test_down(self):
        yield self._check_up_down, False


class TestPathCombinatorCheckConnected(object):
    """
    Unit tests for lib.path_combinator._check_connected
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
        ntools.assert_false(path_combinator._check_connected(up, core, down))

    def test_with_core_down_discon(self):
        up, core, down = self._setup(1, 1, 2, 3)
        ntools.assert_false(path_combinator._check_connected(up, core, down))

    def test_with_core_conn(self):
        up, core, down = self._setup(1, 1, 2, 2)
        ntools.assert_true(path_combinator._check_connected(up, core, down))

    def test_without_core_discon(self):
        up, core, down = self._setup(1, 0, 0, 2)
        ntools.assert_false(path_combinator._check_connected(up, None, down))

    def test_without_core_conn(self):
        up, core, down = self._setup(1, 0, 0, 1)
        ntools.assert_true(path_combinator._check_connected(up, None, down))


class TestPathCombinatorCopyHofs(object):
    """
    Unit tests for lib.path_combinator._copy_hofs
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
        ntools.eq_(path_combinator._copy_hofs(asms), ([3, 2, 1, 0], 0.5))


class TestPathCombinatorCopySegmentShortcut(object):
    """
    Unit tests for lib.path_combinator._copy_segment_shortcut
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

    @patch("lib.path_combinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.path_combinator.copy.deepcopy", new_callable=create_mock)
    def test_up(self, deepcopy, copy_hofs):
        seg, info, hofs, upstream_hof = self._setup(deepcopy, copy_hofs)
        # Call
        ntools.eq_(path_combinator._copy_segment_shortcut(seg, 4),
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

    @patch("lib.path_combinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.path_combinator.copy.deepcopy", new_callable=create_mock)
    def test_down(self, deepcopy, copy_hofs):
        seg, info, hofs, upstream_hof = self._setup(deepcopy, copy_hofs)
        # Call
        ntools.eq_(path_combinator._copy_segment_shortcut(seg, 7, up=False),
                   (info, hofs, upstream_hof, "mtu"))
        # Tests
        ntools.assert_false(info.up_flag)
        copy_hofs.assert_called_once_with(seg.iter_asms.return_value,
                                          reverse=False)
        ntools.eq_(hofs[0].xover, True)
        ntools.eq_(upstream_hof.verify_only, True)


class TestPathCombinatorFindPeerHfs(object):
    """
    Unit tests for lib.path_combinator._find_peer_hfs
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

    def _mk_pcbm(self, inIA, remoteInIF, hof_ingress, mtu):
        hof = create_mock_full({"ingress_if": hof_ingress})
        p = create_mock_full({"remoteInIF": remoteInIF, "inMTU": mtu})
        return create_mock_full({"inIA()": inIA, "p": p, "hof()": hof})

    def test(self):
        up_pcbms, down_pcbms = self._mk_pcbms()
        p = create_mock_full({"hashTreeRoot": b"1234"})
        up_asm = create_mock_full({"isd_as()": "1-1", "iter_pcbms()": up_pcbms,
                                   "p": p})
        down_asm = create_mock_full({"isd_as()": "2-1",
                                     "iter_pcbms()": down_pcbms,
                                     "p": p})
        peer_revs = create_mock_full({"get()": None})
        # Call
        ntools.eq_(path_combinator._find_peer_hfs(up_asm, down_asm, peer_revs),
                   [(up_pcbms[0].hof(), down_pcbms[0].hof(), 500),
                    (up_pcbms[2].hof(), down_pcbms[1].hof(), 700)])

    @patch("lib.path_combinator._skip_peer",
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
        peer_revs = create_mock(["get"])

        def get_side_effect(key):
            data = {("1-1", 3): up_peer_rev, ("2-1", 3): down_peer_rev}
            return data.get(key)

        peer_revs.get.side_effect = get_side_effect

        def skip_peer_side_effect(rev, ht_root):
            if rev in [up_peer_rev, down_peer_rev] and ht_root == b"1234":
                return True
            return False
        skip_peer.side_effect = skip_peer_side_effect

        # Call
        peers = path_combinator._find_peer_hfs(up_asm, down_asm, peer_revs)
        # Tests
        ntools.eq_(peers, [(up_pcbms[0].hof(), down_pcbms[0].hof(), 500)])
        skip_peer.assert_has_calls(
            [call(None, b"1234"), call(up_peer_rev, b"1234")], any_order=True)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
