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
from lib.errors import SCIONParseError
from lib.packet.path import (
    CORE_HOFS,
    CORE_IOF,
    CorePath,
    CrossOverPath,
    DOWN_HOFS,
    DOWN_IOF,
    DOWN_PEERING_HOF,
    DOWN_UPSTREAM_HOF,
    PathBase,
    PathCombinator,
    PeerPath,
    UP_HOFS,
    UP_IOF,
    UP_PEERING_HOF,
    UP_UPSTREAM_HOF,
    parse_path,
)
from lib.packet.opaque_field import OpaqueField
from lib.packet.pcb_ext.mtu import MtuPcbExt
from lib.types import OpaqueFieldType as OFT
from test.testcommon import assert_these_calls, create_mock


# To allow testing of PathBase, despite it having abstract methods.
class PathBaseTesting(PathBase):
    def from_values(self, *args, **kwargs):
        raise NotImplementedError

    def _parse(self, raw):
        raise NotImplementedError

    def get_ad_hops(self):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError


class _FromValuesTest(object):
    """
    Unit tests for lib.packet.path.*.from_values
    """
    @patch("lib.packet.path.PathBase.set_of_idxs", autospec=True)
    @patch("lib.packet.path.PathBase._set_ofs", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def _check(self, ofs, init, set_ofs, set_of_idxs):
        # Call
        inst = self.TYPE.from_values(**ofs)
        # Tests
        ntools.assert_is_instance(inst, self.TYPE)
        calls = []
        for label, arg in zip(inst.OF_ORDER, self.ARGS):
            calls.append(call(inst, label, ofs.get(arg)))
        assert_these_calls(set_ofs, calls)
        set_of_idxs.assert_called_once_with(inst)

    def test_no_args(self):
        yield self._check, {}

    def test_full_args(self):
        args = {}
        for i, arg in enumerate(self.ARGS):
            args[arg] = i
        yield self._check, args


class _GetHofVerTest(object):
    """
    Unit tests for lib.packet.path.*.get_hof_ver
    """
    @patch("lib.packet.path.PathBase.get_hof_ver", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_normal(self, init, super_method):
        inst = self.TYPE()
        hof = create_mock(["info"])
        hof.info = OFT.NORMAL_OF
        inst.get_hof = create_mock()
        inst.get_hof.return_value = hof
        # Call
        ntools.eq_(inst.get_hof_ver(), super_method.return_value)
        # Tests
        super_method.assert_called_once_with(inst)

    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def _check_special(self, ingress, up, exp_hof, exp_idx, init):
        inst = self.TYPE()
        inst.get_hof = create_mock()
        inst.get_hof.return_value = create_mock(["info"])
        iof = create_mock(["up_flag"])
        iof.up_flag = up
        inst.get_iof = create_mock()
        inst.get_iof.return_value = iof
        inst._hof_idx = 10
        inst._get_of = create_mock()
        inst._get_of.return_value = "get_of"
        # Call
        ntools.eq_(inst.get_hof_ver(ingress=ingress), exp_hof)
        # Tests
        if exp_idx:
            inst._get_of.assert_called_once_with(exp_idx)


class TestPathBaseInit(object):
    """
    Unit tests for lib.packet.path.PathBase.__init__
    """
    @patch("lib.packet.path.OpaqueFieldList", autospec=True)
    def test_basic(self, ofl):
        # Call
        inst = PathBaseTesting()
        # Tests
        ntools.assert_is_none(inst._iof_idx)
        ntools.assert_is_none(inst._hof_idx)
        ofl.assert_called_once_with(inst.OF_ORDER)
        ntools.eq_(inst._ofs, ofl.return_value)

    @patch.object(PathBaseTesting, "_parse", autospec=True)
    @patch("lib.packet.path.OpaqueFieldList", autospec=True)
    def test_parse(self, ofl, parse):
        # Call
        inst = PathBaseTesting("raw")
        # Tests
        parse.assert_called_once_with(inst, "raw")


class TestPathBaseSetOfs(object):
    """
    Unit tests for lib.packet.path.PathBase._set_ofs
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_none(self, init):
        inst = PathBaseTesting()
        inst._ofs = create_mock(["set"])
        # Call
        inst._set_ofs("label", None)
        # Tests
        inst._ofs.set.assert_called_once_with("label", [])

    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_list(self, init):
        inst = PathBaseTesting()
        inst._ofs = create_mock(["set"])
        # Call
        inst._set_ofs("label", [1, 2, 3])
        # Tests
        inst._ofs.set.assert_called_once_with("label", [1, 2, 3])

    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_non_list(self, init):
        inst = PathBaseTesting()
        inst._ofs = create_mock(["set"])
        # Call
        inst._set_ofs("label", "value")
        # Tests
        inst._ofs.set.assert_called_once_with("label", ["value"])


class TestPathBaseParseIof(object):
    """
    Unit tests for lib.packet.path.PathBase._parse_iof
    """
    @patch("lib.packet.path.InfoOpaqueField", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init, iof):
        inst = PathBaseTesting()
        data = create_mock(["pop"])
        inst._ofs = create_mock(["set"])
        iof.return_value = create_mock(["hops"])
        # Call
        ntools.eq_(inst._parse_iof(data, "label"), iof.return_value.hops)
        # Tests
        data.pop.assert_called_once_with(iof.LEN)
        iof.assert_called_once_with(data.pop.return_value)
        inst._ofs.set.assert_called_once_with("label", [iof.return_value])


class TestPathBaseParseHofs(object):
    """
    Unit tests for lib.packet.path.PathBase._parse_hofs
    """
    @patch("lib.packet.path.HopOpaqueField", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init, hof):
        inst = PathBaseTesting()
        data = create_mock(["pop"])
        inst._ofs = create_mock(["set"])
        hof.side_effect = ["hof0", "hof1", "hof2"]
        # Call
        inst._parse_hofs(data, "label", 3)
        # Tests
        assert_these_calls(data.pop, [call(hof.LEN)] * 3)
        inst._ofs.set.assert_called_once_with("label", ["hof0", "hof1", "hof2"])


class TestPathBasePack(object):
    """
    Unit tests for lib.packet.path.PathBase.pack
    """
    @patch("lib.packet.path.PathBase.__len__", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init, len_):
        inst = PathBaseTesting()
        len_.return_value = 4
        inst._ofs = create_mock(["pack"])
        inst._ofs.pack.return_value = "data"
        # Call
        ntools.eq_(inst.pack(), "data")


class TestPathBaseReverse(object):
    """
    Unit tests for lib.packet.path.PathBase.reverse
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = PathBaseTesting()
        inst._ofs = create_mock(["__len__", "get_label_by_idx",
                                 "get_idx_by_label", "reverse_label",
                                 "reverse_up_flag", "swap"])
        inst._ofs.get_label_by_idx.return_value = UP_IOF
        inst._ofs.__len__.return_value = 42
        inst._hof_idx = 12
        inst._iof_idx = 0
        inst.set_of_idxs = create_mock()
        # Call
        inst.reverse()
        # Tests
        assert_these_calls(inst._ofs.swap,
                           [call(UP_HOFS, DOWN_HOFS), call(UP_IOF, DOWN_IOF)])
        assert_these_calls(inst._ofs.reverse_up_flag,
                           [call(UP_IOF), call(DOWN_IOF)])
        assert_these_calls(inst._ofs.reverse_label,
                           [call(UP_HOFS), call(DOWN_HOFS)])
        inst._ofs.get_idx_by_label.assert_called_once_with(DOWN_IOF)
        inst.set_of_idxs.assert_called_once_with(
            inst._ofs.get_idx_by_label.return_value, 30)


class TestPathBaseGetOfIdxs(object):
    """
    Unit tests for lib.packet.path.PathBase.get_of_idxs
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = PathBaseTesting()
        inst._iof_idx = "iof"
        inst._hof_idx = "hof"
        # Call
        ntools.eq_(inst.get_of_idxs(), ("iof", "hof"))


class TestPathBaseSetOfIdxs(object):
    """
    Unit tests for lib.packet.path.PathBase.get_of_idxs
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_full(self, init):
        inst = PathBaseTesting()
        # Call
        inst.set_of_idxs("iof", "hof")
        # Tests
        ntools.eq_(inst._iof_idx, "iof")
        ntools.eq_(inst._hof_idx, "hof")

    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_min(self, init):
        inst = PathBaseTesting()
        inst._get_first_iof_idx = create_mock()
        inst._get_first_hof_idx = create_mock()
        # Call
        inst.set_of_idxs()
        # Tests
        ntools.eq_(inst._iof_idx, inst._get_first_iof_idx.return_value)
        ntools.eq_(inst._hof_idx, inst._get_first_hof_idx.return_value)


class TestPathBaseGetIof(object):
    """
    Unit tests for lib.packet.path.PathBase.get_iof
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_none(self, init):
        inst = PathBaseTesting()
        inst._iof_idx = None
        # Call
        ntools.assert_is_none(inst.get_iof())

    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_idx(self, init):
        inst = PathBaseTesting()
        inst._iof_idx = 32
        inst._get_of = create_mock()
        # Call
        ntools.eq_(inst.get_iof(), inst._get_of.return_value)
        # Tests
        inst._get_of.assert_called_once_with(32)


class TestPathBaseGetHof(object):
    """
    Unit tests for lib.packet.path.PathBase.get_hof
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_none(self, init):
        inst = PathBaseTesting()
        inst._hof_idx = None
        # Call
        ntools.assert_is_none(inst.get_hof())

    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_idx(self, init):
        inst = PathBaseTesting()
        inst._hof_idx = 32
        inst._get_of = create_mock()
        # Call
        ntools.eq_(inst.get_hof(), inst._get_of.return_value)
        # Tests
        inst._get_of.assert_called_once_with(32)


class TestPathBaseIncHofIdx(object):
    """
    Unit tests for lib.packet.path.PathBase.inc_hof_idx
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = PathBaseTesting()
        inst._hof_idx = 41
        # Call
        inst.inc_hof_idx()
        # Tests
        ntools.eq_(inst._hof_idx, 42)


class TestPathBaseNextSegment(object):
    """
    Unit tests for lib.packet.path.PathBase.next_segment
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = PathBaseTesting()
        inst.SEGMENT_OFFSETS = 8, 9
        inst._iof_idx = 30
        inst._hof_idx = 42
        # Call
        inst.next_segment()
        # Tests
        ntools.eq_(inst._iof_idx, 50)
        ntools.eq_(inst._hof_idx, 51)


class TestPathBaseGetOf(object):
    """
    Unit tests for lib.packet.path.PathBase._get_of
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = PathBaseTesting()
        inst._ofs = create_mock(["get_by_idx"])
        # Call
        ntools.eq_(inst._get_of(42), inst._ofs.get_by_idx.return_value)
        # Tests
        inst._ofs.get_by_idx.assert_called_once_with(42)


class TestPathBaseGetFirstIofIdx(object):
    """
    Unit tests for lib.packet.path.PathBase.get_first_iof_idx
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_with_ofs(self, init):
        inst = PathBaseTesting()
        inst._ofs = create_mock(["__len__"])
        # Call
        ntools.eq_(inst._get_first_iof_idx(), 0)

    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_without_ofs(self, init):
        inst = PathBaseTesting()
        inst._ofs = create_mock(["__len__"])
        inst._ofs.__len__.return_value = 0
        # Call
        ntools.eq_(inst._get_first_iof_idx(), None)


class TestPathBaseGetOfsByLabel(object):
    """
    Unit tests for lib.packet.path.PathBase.get_ofs_by_label
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = PathBaseTesting()
        inst._ofs = create_mock(["get_by_label"])
        # Call
        ntools.eq_(inst.get_ofs_by_label("label"),
                   inst._ofs.get_by_label.return_value)
        # Tests
        inst._ofs.get_by_label.assert_called_once_with("label")


class TestPathBaseGetHofVer(object):
    """
    Unit tests for lib.packet.path.PathBase.get_hof_ver
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def _check(self, up, expected, init):
        inst = PathBaseTesting()
        iof = create_mock(["up_flag"])
        iof.up_flag = up
        inst.get_iof = create_mock()
        inst.get_iof.return_value = iof
        inst._hof_idx = 10
        inst._get_of = create_mock()
        # Call
        ntools.eq_(inst.get_hof_ver(), inst._get_of.return_value)
        # Tests
        inst._get_of.assert_called_once_with(expected)

    def test(self):
        for up, expected in (
            (True, 11),
            (False, 9)
        ):
            yield self._check, up, expected


class TestPathBaseGetFwdIf(object):
    """
    Unit tests for lib.packet.path.PathBase.get_fwd_if
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def _check(self, up, hof, expected, init):
        inst = PathBaseTesting()
        iof = create_mock(["up_flag"])
        iof.up_flag = up
        inst.get_iof = create_mock()
        inst.get_iof.return_value = iof
        inst.get_hof = create_mock()
        inst.get_hof.return_value = hof
        # Call
        ntools.eq_(inst.get_fwd_if(), expected)

    def test(self):
        hof = create_mock(["egress_if", "ingress_if"])
        for up, expected in (
            (True, hof.ingress_if),
            (False, hof.egress_if)
        ):
            yield self._check, up, hof, expected


class TestPathBaseSetDownpath(object):
    """
    Unit tests for lib.packet.path.PathBase.set_downpath
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = PathBaseTesting()
        iof = create_mock(["up_flag"])
        inst.get_iof = create_mock()
        inst.get_iof.return_value = iof
        # Call
        inst.set_downpath()
        # Tests
        ntools.assert_false(iof.up_flag)


class TestPathBaseIsOnUpPath(object):
    """
    Unit tests for lib.packet.path.PathBase.is_on_up_path
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_iof(self, init):
        inst = PathBaseTesting()
        iof = create_mock(["up_flag"])
        inst.get_iof = create_mock()
        inst.get_iof.return_value = iof
        # Call
        ntools.eq_(inst.is_on_up_path(), iof.up_flag)

    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_no_iof(self, init):
        inst = PathBaseTesting()
        inst.get_iof = create_mock()
        inst.get_iof.return_value = None
        # Call
        ntools.ok_(inst.is_on_up_path())


class TestPathBaseIsLastPathHof(object):
    """
    Unit tests for lib.packet.path.PathBase.is_last_path_hof
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def _check(self, idx, len_, expected, init):
        inst = PathBaseTesting()
        inst._hof_idx = idx
        inst._ofs = range(len_)
        # Call
        ntools.eq_(inst.is_last_path_hof(), expected)

    def test(self):
        for idx, len_, expected in (
            (41, 42, True),
            (0, 42, False),
            (40, 43, False),
            (8, 9, True),
        ):
            yield self._check, idx, len_, expected


class TestPathBaseLen(object):
    """
    Unit tests for lib.packet.path.PathBase.__len__
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = PathBaseTesting()
        inst._ofs = create_mock(["__len__"])
        inst._ofs.__len__.return_value = 42
        # Call
        ntools.eq_(len(inst), 42 * OpaqueField.LEN)


class TestCorePathFromValues(_FromValuesTest):
    """
    Unit tests for lib.packet.path.CorePath.from_values
    """
    TYPE = CorePath
    ARGS = ["up_iof", "up_hofs", "core_iof", "core_hofs", "down_iof",
            "down_hofs"]


class TestCorePathParse(object):
    """
    Unit tests for lib.packet.path.CorePath._parse
    """
    @patch("lib.packet.path.Raw", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def _check(self, raw_len, init, raw):
        # Setup
        inst = CorePath()
        inst._parse_iof = create_mock()
        inst._parse_hofs = create_mock()
        inst.set_of_idxs = create_mock()
        data = create_mock(["__len__"])
        data.__len__.side_effect = raw_len
        raw.return_value = data

        parse_iof_calls = [call(data, i) for i in (UP_IOF, CORE_IOF, DOWN_IOF)]
        parse_hofs_calls = [call(data, i, inst._parse_iof.return_value) for i in
                            (UP_HOFS, CORE_HOFS, DOWN_HOFS)]
        num_calls = sum(raw_len) + 1
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "CorePath")
        assert_these_calls(inst._parse_iof, parse_iof_calls[:num_calls])
        assert_these_calls(inst._parse_hofs, parse_hofs_calls[:num_calls])
        inst.set_of_idxs.assert_called_once_with()

    def test(self):
        for raw_len in ([0, 0], [1, 0], [1, 1]):
            yield self._check, raw_len


class TestCorePathReverse(object):
    """
    Unit tests for lib.packet.path.CorePath.reverse
    """
    @patch("lib.packet.path.PathBase.reverse", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init, super_reverse):
        inst = CorePath()
        inst._ofs = create_mock(["reverse_label", "reverse_up_flag", "count"])
        inst._ofs.count.return_value = False
        # Call
        inst.reverse()
        # Tests
        super_reverse.assert_called_once_with(inst)
        inst._ofs.reverse_up_flag.assert_called_once_with(CORE_IOF)
        inst._ofs.reverse_label.assert_called_once_with(CORE_HOFS)

    @patch("lib.packet.path.PathBase.reverse", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_at_core_down_xovr(self, init, super_reverse):
        inst = CorePath()
        inst._ofs = create_mock(["reverse_label", "reverse_up_flag",
                                 "get_by_label", "count"])
        inst._ofs.count = create_mock()
        inst._ofs.count.return_value = True
        inst._ofs.get_by_label.side_effect = ["foo", "bar"]
        inst.get_hof = create_mock()
        inst.get_hof.return_value = "foo"
        inst.next_segment = create_mock()
        # Call
        inst.reverse()
        # Tests
        inst._ofs.count.assert_called_once_with(UP_HOFS)
        inst.get_hof.assert_called_once_with()
        inst._ofs.get_by_label.assert_called_once_with(UP_HOFS, -1)
        inst.next_segment.assert_called_with()

    @patch("lib.packet.path.PathBase.reverse", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_at_up_core_xovr(self, init, super_reverse):
        inst = CorePath()
        inst._ofs = create_mock(["reverse_label", "reverse_up_flag",
                                 "get_by_label", "count"])
        inst._ofs.count = create_mock()
        inst._ofs.count.return_value = True
        inst._ofs.get_by_label.side_effect = ["foo", "bar"]
        inst.get_hof = create_mock()
        inst.get_hof.return_value = "bar"
        inst.next_segment = create_mock()
        # Call
        inst.reverse()
        # Tests
        assert_these_calls(inst._ofs.count, [call(UP_HOFS), call(CORE_HOFS)])
        assert_these_calls(inst.get_hof, [call(), call()])
        assert_these_calls(inst._ofs.get_by_label, [call(UP_HOFS, -1),
                                                    call(CORE_HOFS, -1)])
        inst.next_segment.assert_called_with()


class TestCorePathGetHofVer(_GetHofVerTest):
    """
    Unit tests for lib.packet.path.CorePath.get_hof_ver
    """
    TYPE = CorePath

    def test_core(self):
        for ingress, up, exp_hof, exp_idx in (
            (True, True, None, None),
            (True, False, "get_of", 9),
            (False, True, "get_of", 11),
            (False, False, None, None),
        ):
            yield self._check_special, ingress, up, exp_hof, exp_idx


class TestCorePathGetAdHops(object):
    """
    Unit tests for lib.packet.path.CorePath.get_ad_hops
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def _check(self, counts, expected, init):
        inst = CorePath()
        inst._ofs = create_mock(["count"])
        inst._ofs.count.side_effect = counts
        # Call
        ntools.eq_(inst.get_ad_hops(), expected)

    def test(self):
        for counts, expected in (
            # [UP_HOFS, CORE_HOFS, DOWN_HOFS]
            ([0, 0, 0], 0),
            ([0, 0, 5], 5),
            ([0, 3, 5], 7),
            ([8, 3, 5], 14),
            ([1, 1, 1], 1),
            ([1, 0, 1], 1),
        ):
            yield self._check, counts, expected


class TestCrossOverPathFromValues(_FromValuesTest):
    """
    Unit tests for lib.packet.path.CrossOverPath.from_values
    """
    TYPE = CrossOverPath
    ARGS = ["up_iof", "up_hofs", "up_upstream_hof",
            "down_iof", "down_upstream_hof", "down_hofs"]


class TestCrossOverPathParse(object):
    """
    Unit tests for lib.packet.path.CrossOverPath._parse
    """
    @patch("lib.packet.path.Raw", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init, raw):
        inst = CrossOverPath()
        inst._parse_iof = create_mock()
        inst._parse_hofs = create_mock()
        inst.set_of_idxs = create_mock()
        data = raw.return_value
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "CrossOverPath")
        assert_these_calls(inst._parse_iof, [
            call(data, UP_IOF), call(data, DOWN_IOF)])
        assert_these_calls(inst._parse_hofs, [
            call(data, UP_HOFS, inst._parse_iof.return_value),
            call(data, UP_UPSTREAM_HOF),
            call(data, DOWN_UPSTREAM_HOF),
            call(data, DOWN_HOFS, inst._parse_iof.return_value),
        ])


class TestCrossOverPathReverse(object):
    """
    Unit tests for lib.packet.path.CrossOverPath.reverse
    """
    @patch("lib.packet.path.PathBase.reverse", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init, super_reverse):
        inst = CrossOverPath()
        inst._ofs = create_mock(["swap", "count"])
        # Call
        inst.reverse()
        # Tests
        super_reverse.assert_called_once_with(inst)
        inst._ofs.swap.assert_called_once_with(UP_UPSTREAM_HOF,
                                               DOWN_UPSTREAM_HOF)

    @patch("lib.packet.path.PathBase.reverse", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_on_path_reverse(self, init, super_reverse):
        inst = CrossOverPath()
        inst._ofs = create_mock(["swap", "count", "get_idx_by_label"])
        inst._ofs.count.return_value = 1
        inst._ofs.get_idx_by_label.side_effect = [1, 2, 4]
        inst._hof_idx = 1
        inst.set_downpath = create_mock()
        # Call
        inst.reverse()
        # Tests
        super_reverse.assert_called_once_with(inst)
        inst._ofs.swap.assert_called_once_with(UP_UPSTREAM_HOF,
                                               DOWN_UPSTREAM_HOF)
        assert_these_calls(inst._ofs.get_idx_by_label,
                           [call(UP_HOFS), call(DOWN_IOF), call(DOWN_HOFS)])
        ntools.eq_(inst._iof_idx, 2)
        ntools.eq_(inst._hof_idx, inst._iof_idx + 2)
        inst.set_downpath.assert_called_once_with()


class TestCrossOverPathGetFirstHofIdx(object):
    """
    Unit tests for lib.packet.path.CrossOverPath._get_first_hof_idx
    """
    @patch("lib.packet.path.PathBase._get_first_hof_idx", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def _check(self, counts, expected, init, super_method):
        inst = CrossOverPath()
        inst._ofs = create_mock(["count"])
        inst._ofs.count.side_effect = counts
        super_method.return_value = 99
        # Call
        ntools.eq_(inst._get_first_hof_idx(), expected)

    def test(self):
        for counts, expected in (
            ([1], 5), ([2], 1), ([0, 1], 1), ([0, 0], 99)
        ):
            yield self._check, counts, expected


class TestCrossOverPathGetFirstIofIdx(object):
    """
    Unit tests for lib.packet.path.CrossOverPath._get_first_iof_idx
    """
    @patch("lib.packet.path.PathBase._get_first_iof_idx", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def _check(self, count, expected, init, super_method):
        inst = CrossOverPath()
        inst._ofs = create_mock(["count"])
        inst._ofs.count.return_value = count
        super_method.return_value = 99
        # Call
        ntools.eq_(inst._get_first_iof_idx(), expected)

    def test(self):
        for count, expected in (
            (1, 3), (2, 99), (0, 99)
        ):
            yield self._check, count, expected


class TestCrossOverPathGetHofVer(_GetHofVerTest):
    """
    Unit tests for lib.packet.path.CrossOverPath.get_hof_ver
    """
    TYPE = CrossOverPath

    def test_xovr(self):
        for ingress, up, exp_hof, exp_idx in (
            (True, True, "get_of", 11),
            (True, False, "get_of", 9),
            (False, False, "get_of", 9),
        ):
            yield self._check_special, ingress, up, exp_hof, exp_idx


class TestCrossOverPathGetAdHops(object):
    """
    Unit tests for lib.packet.path.CrossOverPath.get_ad_hops
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = CrossOverPath()
        inst._ofs = create_mock(["count"])
        inst._ofs.count.side_effect = [3, 5]
        # Call
        ntools.eq_(inst.get_ad_hops(), 7)


class TestPeerPathFromValues(_FromValuesTest):
    """
    Unit tests for lib.packet.path.PeerPath.from_values
    """
    TYPE = PeerPath
    ARGS = ["up_iof", "up_hofs", "up_peering_hof", "up_upstream_hof",
            "down_iof", "down_upstream_hof", "down_peering_hof", "down_hofs"]


class TestPeerPathParse(object):
    """
    Unit tests for lib.packet.path.PeerPath._parse
    """
    @patch("lib.packet.path.Raw", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_basic(self, init, raw):
        inst = PeerPath()
        inst._parse_iof = create_mock()
        inst._parse_hofs = create_mock()
        inst.set_of_idxs = create_mock()
        data = raw.return_value
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "PeerPath")
        assert_these_calls(inst._parse_iof, [
            call(data, UP_IOF), call(data, DOWN_IOF)])
        assert_these_calls(inst._parse_hofs, [
            call(data, UP_HOFS, inst._parse_iof.return_value),
            call(data, UP_PEERING_HOF),
            call(data, UP_UPSTREAM_HOF),
            call(data, DOWN_UPSTREAM_HOF),
            call(data, DOWN_PEERING_HOF),
            call(data, DOWN_HOFS, inst._parse_iof.return_value),
        ])
        inst.set_of_idxs.assert_called_once_with()


class TestPeerPathReverse(object):
    """
    Unit tests for lib.packet.path.PeerPath.reverse
    """
    @patch("lib.packet.path.PathBase.reverse", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init, super_reverse):
        inst = PeerPath()
        inst._ofs = create_mock(["swap", "get_by_label"])
        inst.get_by_idx = create_mock()
        inst.get_hof = create_mock()
        # Call
        inst.reverse()
        # Tests
        super_reverse.assert_called_once_with(inst)
        assert_these_calls(inst._ofs.swap, [
            call(UP_UPSTREAM_HOF, DOWN_UPSTREAM_HOF),
            call(UP_PEERING_HOF, DOWN_PEERING_HOF),
        ])

    @patch("lib.packet.path.PathBase.reverse", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test_peering_point(self, init, super_reverse):
        inst = PeerPath()
        inst._ofs = create_mock(["swap", "get_by_label", "get_idx_by_label"])
        inst.get_by_idx = create_mock()
        inst.get_hof = create_mock()
        inst.get_hof.return_value = inst._ofs.get_by_label.return_value
        inst.inc_hof_idx = create_mock()
        inst._hof_idx = inst._ofs.get_idx_by_label.return_value
        # Call
        inst.reverse()
        # Tests
        super_reverse.assert_called_once_with(inst)
        assert_these_calls(inst._ofs.swap, [
            call(UP_UPSTREAM_HOF, DOWN_UPSTREAM_HOF),
            call(UP_PEERING_HOF, DOWN_PEERING_HOF),
        ])
        inst.inc_hof_idx.assert_called_once_with()
        inst._ofs.get_idx_by_label.assert_called_once_with(UP_PEERING_HOF)


class TestPeerPathGetHofVer(_GetHofVerTest):
    """
    Unit tests for lib.packet.path.PeerPath.get_hof_ver
    """
    TYPE = PeerPath

    def test_peer(self):
        for ingress, up, exp_hof, exp_idx in (
            (True, True, "get_of", 12),
            (True, False, "get_of", 11),
            (False, True, "get_of", 9),
            (False, False, "get_of", 8),
        ):
            yield self._check_special, ingress, up, exp_hof, exp_idx


class TestPeerPathGetFirstHofIdx(object):
    """
    Unit tests for lib.packet.path.PeerPath._get_first_hof_idx
    """
    @patch("lib.packet.path.PathBase._get_first_hof_idx", autospec=True)
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def _check(self, hofs, expected, init, super_method):
        inst = PeerPath()
        inst._ofs = create_mock(["get_by_label"])
        inst._ofs.get_by_label.side_effect = hofs
        super_method.return_value = 99
        # Call
        ntools.eq_(inst._get_first_hof_idx(), expected)

    def test_no_hofs(self):
        self._check([None, None], 99)

    def test_up_hofs_normal(self):
        hof = create_mock(["info"])
        self._check([[hof], None], 1)

    def test_up_hofs_xovr(self):
        hof = create_mock(["info"])
        hof.info = OFT.XOVR_POINT
        self._check([[hof], None], 2)

    def test_down_hofs_normal(self):
        hof = create_mock(["info"])
        self._check([None, [hof]], 1)

    def test_down_hofs_xovr(self):
        hof = create_mock(["info"])
        hof.info = OFT.XOVR_POINT
        self._check([None, [hof]], 2)


class TestPeerPathGetAdHops(object):
    """
    Unit tests for lib.packet.path.PeerPath.get_ad_hops
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = PeerPath()
        inst._ofs = create_mock(["count"])
        inst._ofs.count.side_effect = [3, 5]
        # Call
        ntools.eq_(inst.get_ad_hops(), 7)


class PathCombinatorBase(object):
    def _generate_none(self):
        def _mk_seg(ads):
            seg = create_mock(["ads"])
            seg.ads = ads
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
        up, down = create_mock(['ads']), create_mock(['ads'])
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
        up, down = create_mock(['ads']), create_mock(['ads'])
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
        up, core, down = (create_mock(['ads']), create_mock(['ads']),
                          create_mock(['ads']))
        check_connected.return_value = False
        # Call
        ntools.assert_is_none(PathCombinator._build_core_path(up, core, down))
        # Tests
        check_connected.assert_called_once_with(up, core, down)

    @patch("lib.packet.path.CorePath.from_values", new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._copy_segment",
           new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._check_connected",
           new_callable=create_mock)
    def test_full(self, check_connected, copy_seg, core_from_values):
        up = create_mock(['ads'])
        core = create_mock(['ads'])
        down = create_mock(['ads'])
        up.ads = [create_mock(['pcbm', 'ext']) for i in range(6)]
        mtus = [i * 100 for i in range(11)]
        idx = 3  # MTUs: 300, 400, 500, 600, 700, 800
        for m in up.ads:
            m.pcbm = create_mock(['isd_id', 'ad_id', 'hof'])
            m.pcbm.hof = create_mock(['egress_if', 'ingress_if'])
            m.ext = create_mock(['EXT_TYPE', 'mtu'])
            m.ext.EXT_TYPE = MtuPcbExt.EXT_TYPE
            m.ext.mtu = mtus[idx]
            idx += 1
        core.ads = [create_mock(['pcbm', 'ext']) for i in range(6)]
        idx = 5  # MTUs: 500, 400, 300, 200, 100, 0 (invalid)
        for m in core.ads:
            m.pcbm = create_mock(['isd_id', 'ad_id', 'hof'])
            m.pcbm.hof = create_mock(['egress_if', 'ingress_if'])
            m.ext = create_mock(['EXT_TYPE', 'mtu'])
            m.ext.EXT_TYPE = MtuPcbExt.EXT_TYPE
            m.ext.mtu = mtus[idx]
            idx -= 1
        down.ads = [create_mock(['pcbm', 'ext']) for i in range(6)]
        idx = 2  # MTUs: 200, 300, 400, 500, 600, 700
        for m in down.ads:
            m.pcbm = create_mock(['isd_id', 'ad_id', 'hof'])
            m.pcbm.hof = create_mock(['egress_if', 'ingress_if'])
            m.ext = create_mock(['EXT_TYPE', 'mtu'])
            m.ext.EXT_TYPE = MtuPcbExt.EXT_TYPE
            m.ext.mtu = mtus[idx]
            idx += 1

        check_connected.return_value = True
        copy_seg.side_effect = [
            ("up_iof", "up_hofs", 300),
            ("core_iof", "core_hofs", 100),  # smallest valid MTU is 100
            ("down_iof", "down_hofs", 200),
        ]
        # Call
        ntools.eq_(PathCombinator._build_core_path(up, core, down),
                   core_from_values.return_value)
        # Tests
        assert_these_calls(copy_seg, [
            call(up, [-1]), call(core, [-1, 0]), call(down, [0], up=False)
        ])
        core_from_values.assert_called_once_with(
            "up_iof", "up_hofs", "core_iof", "core_hofs", "down_iof",
            "down_hofs")


class TestPathCombinatorCopySegment(object):
    """
    Unit tests for lib.packet.path.PathCombinator._copy_segment
    """
    def test_no_segment(self):
        ntools.eq_(PathCombinator._copy_segment(None, "xovrs"),
                   (None, None, None))

    @patch("lib.packet.path.PathCombinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.packet.path.copy.deepcopy", autospec=True)
    def test_copy_up(self, deepcopy, copy_hofs):
        seg = create_mock(["ads", "iof"])
        iof = create_mock(["up_flag"])
        deepcopy.return_value = iof
        hofs = []
        for _ in range(3):
            hof = create_mock(["info"])
            hof.info = OFT.NORMAL_OF
            hofs.append(hof)
        copy_hofs.return_value = hofs, None
        # Call
        ntools.eq_(PathCombinator._copy_segment(seg, [0, 2]), (iof, hofs, None))
        # Tests
        deepcopy.assert_called_once_with(seg.iof)
        ntools.eq_(iof.up_flag, True)
        copy_hofs.assert_called_once_with(seg.ads, reverse=True)
        ntools.eq_(hofs[0].info, OFT.XOVR_POINT)
        ntools.eq_(hofs[1].info, OFT.NORMAL_OF)
        ntools.eq_(hofs[2].info, OFT.XOVR_POINT)

    @patch("lib.packet.path.PathCombinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.packet.path.copy.deepcopy", autospec=True)
    def test_copy_down(self, deepcopy, copy_hofs):
        seg = create_mock(["ads", "iof"])
        iof = create_mock(["up_flag"])
        deepcopy.return_value = iof
        copy_hofs.return_value = "hofs", None
        # Call
        ntools.eq_(PathCombinator._copy_segment(seg, [], up=False),
                   (iof, "hofs", None))
        # Tests
        copy_hofs.assert_called_once_with(seg.ads, reverse=False)


class TestPathCombinatorGetXovrPeer(object):
    """
    Unit tests for lib.packet.path.PathCombinator._get_xovr_peer
    """
    def _gen_segment(self, n, pms=4):
        seg = create_mock(['ads'])
        ads = []
        for i in range(n):
            ad = create_mock(['pcbm', 'pms'])
            ad.pcbm = create_mock(['ad_id', 'isd_id'])
            ad.pms = []
            for j in range(pms):
                ad.pms.append(create_mock(['ad_id', 'isd_id']))
            ads.append(ad)
        seg.ads = ads
        return seg

    def _setup_xovr_points(self, up, down):
        up.ads[1].pcbm.ad_id = down.ads[6].pcbm.ad_id
        up.ads[1].pcbm.isd_id = down.ads[6].pcbm.isd_id
        up.ads[3].pcbm.ad_id = down.ads[2].pcbm.ad_id
        up.ads[3].pcbm.isd_id = down.ads[2].pcbm.isd_id
        return (1, 6)

    def _setup_peer_points(self, up, down):
        up.ads[2].pms[1].ad_id = down.ads[5].pcbm.ad_id
        up.ads[2].pms[1].isd_id = down.ads[5].pcbm.isd_id
        down.ads[5].pms[2].ad_id = up.ads[2].pcbm.ad_id
        down.ads[5].pms[2].isd_id = up.ads[2].pcbm.isd_id
        up.ads[4].pms[0].ad_id = down.ads[1].pcbm.ad_id
        up.ads[4].pms[0].isd_id = down.ads[1].pcbm.isd_id
        down.ads[1].pms[1].ad_id = up.ads[4].pcbm.ad_id
        down.ads[1].pms[1].isd_id = up.ads[4].pcbm.isd_id
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
    @patch("lib.packet.path.CrossOverPath.from_values",
           new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._copy_segment_shortcut",
           new_callable=create_mock)
    def test_xovr(self, join_shortcuts, xovr_from_values):
        up_iof = create_mock(["info"])
        down_iof = create_mock(["info"])
        up_seg = create_mock(['ads'])
        down_seg = create_mock(['ads'])
        up_seg.ads = [create_mock(['pcbm', 'ext']) for i in range(6)]
        mtus = [i * 100 for i in range(11)]
        idx = 1
        for m in up_seg.ads:
            m.pcbm = create_mock(['isd_id', 'ad_id', 'hof'])
            m.pcbm.hof = create_mock(['egress_if', 'ingress_if'])
            m.ext = create_mock(['EXT_TYPE', 'mtu'])
            m.ext.EXT_TYPE = MtuPcbExt.EXT_TYPE
            m.ext.mtu = mtus[idx]
            idx += 1
        down_seg.ads = [create_mock(['pcbm', 'ext']) for i in range(6)]
        idx = 10
        for m in down_seg.ads:
            m.pcbm = create_mock(['isd_id', 'ad_id', 'hof'])
            m.pcbm.hof = create_mock(['egress_if', 'ingress_if'])
            m.ext = create_mock(['EXT_TYPE', 'mtu'])
            m.ext.EXT_TYPE = MtuPcbExt.EXT_TYPE
            m.ext.mtu = mtus[idx]
            idx -= 1

        join_shortcuts.side_effect = [
            (up_iof, "up_hofs", "up_upstream_hof", 100),
            (down_iof, "down_hofs", "down_upstream_hof", 400),
        ]
        # Call
        ntools.eq_(
            PathCombinator._join_shortcuts(up_seg, down_seg, (2, 5), False),
            xovr_from_values.return_value)
        # Tests
        ntools.eq_(up_iof.info, OFT.SHORTCUT)
        ntools.eq_(down_iof.info, OFT.SHORTCUT)
        assert_these_calls(join_shortcuts, [
            call(up_seg, 2), call(down_seg, 5, up=False)])
        xovr_from_values.assert_called_once_with(
            up_iof, "up_hofs", "up_upstream_hof",
            down_iof, "down_upstream_hof", "down_hofs")

    @patch("lib.packet.path.PeerPath.from_values", new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._join_shortcuts_peer",
           new_callable=create_mock)
    @patch("lib.packet.path.PathCombinator._copy_segment_shortcut",
           new_callable=create_mock)
    def _check_peer(self, of_type, join_shortcuts, join_peer,
                    peer_path):
        up_seg = create_mock(['get_isd', 'ads'])
        down_seg = create_mock(['get_isd', 'ads'])
        if of_type == OFT.INTRA_ISD_PEER:
            up_seg.get_isd.return_value = down_seg.get_isd.return_value
        up_seg.ads = [create_mock(['pcbm']) for i in range(6)]
        for m in up_seg.ads:
            m.pcbm = create_mock(['isd_id', 'ad_id', 'hof'])
            m.pcbm.hof = create_mock(['egress_if', 'ingress_if'])
        down_seg.ads = [create_mock(['pcbm']) for i in range(6)]
        for m in down_seg.ads:
            m.pcbm = create_mock(['isd_id', 'ad_id', 'hof'])
            m.pcbm.hof = create_mock(['egress_if', 'ingress_if'])
        up_iof = create_mock(["info"])
        down_iof = create_mock(["info"])
        join_shortcuts.side_effect = [
            (up_iof, "up_hofs", "up_upstream_hof", None),
            (down_iof, "down_hofs", "down_upstream_hof", None),
        ]
        up_peering_hof = create_mock(['ingress_if'])
        down_peering_hof = create_mock(['ingress_if'])
        join_peer.return_value = [up_peering_hof, down_peering_hof]
        # Call
        ntools.eq_(
            PathCombinator._join_shortcuts(up_seg, down_seg, (2, 5), True),
            peer_path.return_value)
        # Tests
        ntools.eq_(up_iof.info, of_type)
        ntools.eq_(down_iof.info, of_type)
        join_peer.assert_called_once_with(up_seg.ads[2], down_seg.ads[5])
        peer_path.assert_called_once_with(
            up_iof, "up_hofs", up_peering_hof, "up_upstream_hof",
            down_iof, "down_upstream_hof", down_peering_hof, "down_hofs")

    def test_peer(self):
        for of_type in (OFT.INTRA_ISD_PEER,
                        OFT.INTER_ISD_PEER):
            yield self._check_peer, of_type


class TestPathCombinatorCheckConnected(object):
    """
    Unit tests for lib.packet.path.PathCombinator._check_connected
    """
    def _setup(self, up_first=None, core_last=None, core_first=None,
               down_first=None):
        segs = []
        for part in ["up", "core", "down"]:
            seg = create_mock(['get_first_pcbm', 'get_last_pcbm'])
            pcbm = create_mock(['ad_id', 'isd_id'])
            seg.get_first_pcbm.return_value = pcbm
            first = "%s_first" % part
            if locals().get(first):
                pcbm.ad_id = locals()[first]
                pcbm.isd_id = locals()[first]
            pcbm = create_mock(['ad_id', 'isd_id'])
            seg.get_last_pcbm.return_value = pcbm
            last = "%s_last" % part
            if locals().get(last):
                pcbm.ad_id = locals()[last]
                pcbm.isd_id = locals()[last]
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
        seg = create_mock(["iof", "ads"])
        seg.ads = []
        for _ in range(10):
            ad = create_mock(["pcbm"])
            ad.pcbm = create_mock(["hof"])
            seg.ads.append(ad)
        iof = create_mock(["hops", "up_flag"])
        iof.hops = 10
        hofs = []
        for _ in range(6):
            hofs.append(create_mock(["info"]))
        copy_hofs.return_value = hofs, None
        upstream_hof = create_mock(["info"])
        deepcopy.side_effect = [iof, upstream_hof]
        return seg, iof, hofs, upstream_hof

        # Call
        ntools.eq_(PathCombinator._copy_segment_shortcut(seg, 4),
                   (iof, hofs, upstream_hof, None))
        # Tests
        assert_these_calls(deepcopy, [call(seg.iof), call(seg.ads[3].pcbm.hof)])
        ntools.eq_(iof.hops, 6)
        ntools.ok_(iof.up_flag)
        copy_hofs.assert_called_once_with(seg.ads[4:], reverse=True)
        ntools.eq_(hofs[-1].info, OFT.XOVR_POINT)
        ntools.eq_(upstream_hof.info, OFT.NORMAL_OF)

    @patch("lib.packet.path.PathCombinator._copy_hofs",
           new_callable=create_mock)
    @patch("lib.packet.path.copy.deepcopy", new_callable=create_mock)
    def test_up(self, deepcopy, copy_hofs):
        seg, iof, hofs, upstream_hof = self._setup(deepcopy, copy_hofs)
        # Call
        ntools.eq_(PathCombinator._copy_segment_shortcut(seg, 4),
                   (iof, hofs, upstream_hof, None))
        # Tests
        assert_these_calls(deepcopy, [call(seg.iof), call(seg.ads[3].pcbm.hof)])
        ntools.eq_(iof.hops, 6)
        ntools.ok_(iof.up_flag)
        copy_hofs.assert_called_once_with(seg.ads[4:], reverse=True)
        ntools.eq_(hofs[-1].info, OFT.XOVR_POINT)
        ntools.eq_(upstream_hof.info, OFT.NORMAL_OF)

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
        copy_hofs.assert_called_once_with(seg.ads[7:], reverse=False)
        ntools.eq_(hofs[0].info, OFT.XOVR_POINT)


class TestPathCombinatorJoinShortcutsPeer(object):
    """
    Unit tests for lib.packet.path.PathCombinator._join_shortcuts_peer
    """
    def test(self):
        up_ad = create_mock(['pms', 'pcbm'])
        up_ad.pcbm = create_mock(['ad_id', 'isd_id'])
        up_ad.pcbm.ad_id = 1
        up_ad.pcbm.isd_id = 1
        down_ad = create_mock(['pms', 'pcbm'])
        down_ad.pcbm = create_mock(['ad_id', 'isd_id'])
        down_ad.pcbm.ad_id = 2
        down_ad.pcbm.isd_id = 1
        up_ad.pms = [create_mock(['ad_id', 'hof']) for i in range(2)]
        down_ad.pms = [create_mock(['ad_id', 'hof']) for i in range(3)]
        up_ad.pms[1].ad_id = 2
        up_ad.pms[1].hof = 'up_hof1'
        down_ad.pms[0].ad_id = 1
        down_ad.pms[0].hof = 'down_hof0'
        ntools.eq_(PathCombinator._join_shortcuts_peer(up_ad, down_ad),
                   ("up_hof1", "down_hof0"))


class TestParsePath(object):
    """
    Unit tests for lib.packet.path.parse_path
    """
    @patch("lib.packet.path.EmptyPath", autospec=True)
    def test_empty(self, empty):
        ntools.eq_(parse_path(""), empty.return_value)

    @patch("lib.packet.path.PeerPath", autospec=True)
    @patch("lib.packet.path.CrossOverPath", autospec=True)
    @patch("lib.packet.path.CorePath", autospec=True)
    @patch("lib.packet.path.InfoOpaqueField", autospec=True)
    def _check_paths(self, info_type, class_name, iof, core, xover, peer):
        class_map = {"core": core, "xover": xover, "peer": peer}
        class_ = class_map[class_name]
        info = create_mock(["info"])
        info.info = info_type
        iof.return_value = info
        iof.LEN = 10
        # Call
        ntools.eq_(parse_path(range(20)), class_.return_value)
        # Tests
        iof.assert_called_once_with(range(10))
        class_.assert_called_once_with(range(20))

    def test_paths(self):
        for info_type, class_name in (
            (OFT.CORE, "core"),
            (OFT.SHORTCUT, "xover"),
            (OFT.INTRA_ISD_PEER, "peer"),
            (OFT.INTER_ISD_PEER, "peer"),
        ):
            yield self._check_paths, info_type, class_name

    @patch("lib.packet.path.InfoOpaqueField", autospec=True)
    def test_unknown(self, iof):
        iof.return_value = create_mock(["info"])
        ntools.assert_raises(SCIONParseError, parse_path, range(1))


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
