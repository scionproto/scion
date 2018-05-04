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
from unittest.mock import patch, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.path import SCIONPath
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
             "reverse_label", "reverse_cons_dir_flag", "swap"])
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
        assert_these_calls(inst._ofs.reverse_cons_dir_flag,
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
    def _setup(self, xover=False, peer=False, shortcut=False, cons_dir_flag=False):
        inst = SCIONPath()
        inst._iof_idx = 0
        inst._hof_idx = 0
        iof = create_mock(["peer", "shortcut", "cons_dir_flag"])
        iof.peer = peer
        iof.shortcut = shortcut
        iof.cons_dir_flag = cons_dir_flag
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

    def _check_xover_peer(self, ingress, cons_dir, expected):
        inst, iof, hof = self._setup(xover=True, shortcut=True, peer=True,
                                     cons_dir_flag=cons_dir)
        # Call
        ntools.eq_(inst.get_hof_ver(ingress=ingress),
                   inst._ofs.get_by_idx.return_value)
        # Tests
        inst._ofs.get_by_idx.assert_called_once_with(expected)

    def test_xover_peer(self):
        for ingress, cons_dir, exp in (
            (True, False, 2), (True, True, 1),
            (False, False, -1), (False, True, -2)
        ):
            yield self._check_xover_peer, ingress, cons_dir, exp

    def _check_xover_normal(self, ingress, cons_dir, expected):
        inst, iof, hof = self._setup(xover=True, cons_dir_flag=cons_dir)
        # Call
        ret = inst.get_hof_ver(ingress=ingress)
        # Tests
        if expected is None:
            ntools.eq_(ret, None)
        else:
            ntools.eq_(ret, inst._ofs.get_by_idx.return_value)
            inst._ofs.get_by_idx.assert_called_once_with(expected)

    def test_xover_normal(self):
        for ingress, cons_dir, exp in (
            (True, False, None), (True, True, -1),
            (False, False, +1), (False, True, None)
        ):
            yield self._check_xover_normal, ingress, cons_dir, exp


class TestSCIONPathGetHofVerNormal(object):
    """
    Unit tests for lib.packet.path.SCIONPath._get_hof_ver_normal
    """
    def _check(self, cons_dir, hof_idx, expected):
        inst = SCIONPath()
        inst._iof_idx = 0
        inst._hof_idx = hof_idx
        inst._ofs = create_mock(["get_by_idx"])
        iof = create_mock(["hops", "cons_dir_flag"])
        iof.hops = 5
        iof.cons_dir_flag = cons_dir
        # Call
        ret = inst._get_hof_ver_normal(iof)
        # Tests
        if expected is None:
            ntools.eq_(ret, None)
        else:
            ntools.eq_(ret, inst._ofs.get_by_idx.return_value)
            inst._ofs.get_by_idx.assert_called_once_with(expected)

    def test(self):
        for cons_dir, hof_idx, exp in (
            (False, 1, 2), (False, 4, 5), (False, 5, None),
            (True, 1, None), (True, 2, 1), (True, 5, 4),
        ):
            yield self._check, cons_dir, hof_idx, exp


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


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
