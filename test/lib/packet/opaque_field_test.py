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
:mod:`lib_packet_opaque_field_test` --- lib.packet.opaque_field unit tests
==========================================================================
"""
# Stdlib
from unittest.mock import MagicMock, call, patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONIndexError, SCIONKeyError
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
    OpaqueField,
    OpaqueFieldList,
)
from test.testcommon import create_mock


# To allow testing of OpaqueField, despite it having abstract methods.
class OpaqueFieldTesting(OpaqueField):
    def parse(self, raw):
        pass

    def pack(self):
        pass

    def __str__(self):
        pass


class TestOpaqueFieldIsRegular(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueField.is_regular
    """
    def test_basic(self):
        op_fld = OpaqueFieldTesting()
        op_fld.info = 0b10111111
        ntools.assert_true(op_fld.is_regular())

    def test_set(self):
        op_fld = OpaqueFieldTesting()
        op_fld.info = 0b01000000
        ntools.assert_false(op_fld.is_regular())


class TestOpaqueFieldIsContinue(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueField.is_continue
    """
    def test_basic(self):
        op_fld = OpaqueFieldTesting()
        op_fld.info = 0b11011111
        ntools.assert_false(op_fld.is_continue())

    def test_set(self):
        op_fld = OpaqueFieldTesting()
        op_fld.info = 0b00100000
        ntools.assert_true(op_fld.is_continue())


class TestOpaqueFieldIsXovr(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueField.is_xovr
    """
    def test_basic(self):
        op_fld = OpaqueFieldTesting()
        op_fld.info = 0b11101111
        ntools.assert_false(op_fld.is_xovr())

    def test_set(self):
        op_fld = OpaqueFieldTesting()
        op_fld.info = 0b00010000
        ntools.assert_true(op_fld.is_xovr())


class TestHopOpaqueFieldInit(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.__init__
    """
    def test_basic(self):
        hop_op_fld = HopOpaqueField()
        ntools.eq_(hop_op_fld.exp_time, 0)
        ntools.eq_(hop_op_fld.ingress_if, 0)
        ntools.eq_(hop_op_fld.egress_if, 0)
        ntools.eq_(hop_op_fld.mac, b'\x00' * 3)

    @patch("lib.packet.opaque_field.HopOpaqueField.parse", autospec=True)
    def test_raw(self, parse):
        hop_op_fld = HopOpaqueField("data")
        parse.assert_called_once_with(hop_op_fld, "data")


class TestHopOpaqueFieldParse(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.parse
    """
    @patch("lib.packet.opaque_field.Raw", autospec=True)
    def test_basic(self, raw):
        # Setup
        hop_op_fld = HopOpaqueField()
        data = bytes.fromhex('0e 2a 0a 0b 0c') + b'\x01' * 3
        raw.return_value = MagicMock(spec_set=["pop"])
        raw.return_value.pop.side_effect = (
            data[:2], data[2:5], data[5:8])
        # Call
        hop_op_fld.parse(data)
        # Tests
        raw.assert_called_once_with(data, "HopOpaqueField", hop_op_fld.LEN)
        raw.return_value.pop.assert_has_calls([call(2), call(3), call(3)])
        ntools.eq_(hop_op_fld.raw, data)
        ntools.eq_(hop_op_fld.info, 0x0e)
        ntools.eq_(hop_op_fld.exp_time, 0x2a)
        ntools.eq_(hop_op_fld.mac, b'\x01' * 3)
        ntools.eq_(hop_op_fld.ingress_if, 0x0a0)
        ntools.eq_(hop_op_fld.egress_if, 0xb0c)


class TestHopOpaqueFieldFromValues(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.from_values
    """
    def test_basic(self):
        hop_op_fld = HopOpaqueField.from_values(42, 160, 2828, b'\x01' * 3)
        ntools.eq_(hop_op_fld.exp_time, 42)
        ntools.eq_(hop_op_fld.ingress_if, 160)
        ntools.eq_(hop_op_fld.egress_if, 2828)
        ntools.eq_(hop_op_fld.mac, b'\x01' * 3)

    def test_less_arg(self):
        hop_op_fld = HopOpaqueField.from_values(42)
        ntools.eq_(hop_op_fld.exp_time, 42)
        ntools.eq_(hop_op_fld.ingress_if, 0)
        ntools.eq_(hop_op_fld.egress_if, 0)
        ntools.eq_(hop_op_fld.mac, b'\x00' * 3)


class TestHopOpaqueFieldPack(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.pack
    """
    def test_basic(self):
        hop_op_fld = HopOpaqueField()
        hop_op_fld.info = 0x0e
        hop_op_fld.exp_time = 0x2a
        hop_op_fld.ingress_if = 0x0a0
        hop_op_fld.egress_if = 0xb0c
        hop_op_fld.mac = b'\x01' * 3
        data = bytes.fromhex('0e 2a 0a 0b 0c') + b'\x01' * 3
        ntools.eq_(hop_op_fld.pack(), data)


class TestInfoOpaqueFieldParse(object):
    """
    Unit tests for lib.packet.opaque_field.InfoOpaqueField.parse
    """
    @patch("lib.packet.opaque_field.Raw", autospec=True)
    def test_basic(self, raw):
        # Setup
        inf_op_fld = InfoOpaqueField()
        data = bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f')
        raw.return_value = MagicMock(spec_set=["pop"])
        raw.return_value.pop.return_value = data
        # Call
        inf_op_fld.parse(data)
        # Tests
        raw.assert_called_once_with(data, "InfoOpaqueField", inf_op_fld.LEN)
        ntools.eq_(inf_op_fld.raw, data)
        ntools.eq_(inf_op_fld.info, 0x0f >> 1)
        ntools.eq_(inf_op_fld.timestamp, 0x2a0a0b0c)
        ntools.eq_(inf_op_fld.isd, 0x0d0e)
        ntools.eq_(inf_op_fld.hops, 0x0f)
        ntools.eq_(inf_op_fld.up_flag, 0x0f & 0x01)


class TestInfoOpaqueFieldFromValues(object):
    """
    Unit tests for lib.packet.opaque_field.InfoOpaqueField.from_values
    """
    def test_basic(self):
        inf_op_fld = InfoOpaqueField.from_values(7, True, 705301260, 3342, 15)
        ntools.eq_(inf_op_fld.info, 7)
        ntools.eq_(inf_op_fld.timestamp, 705301260)
        ntools.eq_(inf_op_fld.isd, 3342)
        ntools.eq_(inf_op_fld.hops, 15)
        ntools.assert_true(inf_op_fld.up_flag)

    def test_less_arg(self):
        inf_op_fld = InfoOpaqueField.from_values()
        ntools.eq_(inf_op_fld.info, 0)
        ntools.eq_(inf_op_fld.timestamp, 0)
        ntools.eq_(inf_op_fld.isd, 0)
        ntools.eq_(inf_op_fld.hops, 0)
        ntools.assert_false(inf_op_fld.up_flag)


class TestInfoOpaqueFieldPack(object):
    """
    Unit tests for lib.packet.opaque_field.InfoOpaqueField.pack
    """
    def test_basic(self):
        inf_op_fld = InfoOpaqueField()
        inf_op_fld.info = 0x0f >> 1
        inf_op_fld.timestamp = 0x2a0a0b0c
        inf_op_fld.isd = 0x0d0e
        inf_op_fld.hops = 0x0f
        inf_op_fld.up_flag = 0x0f & 0x01
        ntools.eq_(inf_op_fld.pack(), bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f'))


class TestOpaqueFieldListInit(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueFieldList.__init__
    """
    def test(self):
        order = ["up", "down", "core"]
        # Call
        inst = OpaqueFieldList(order)
        # Tests
        ntools.eq_(inst._order, order)
        ntools.eq_(inst._labels, {
            "up": [],
            "down": [],
            "core": [],
        })


def _of_list_setup():
    order = ["up", "down", "core"]
    inst = OpaqueFieldList(order)
    inst._labels = {
        "up": ["up0", "up1", "up2"],
        "down": [],
        "core": ["core0"],
    }
    return inst


class TestOpaqueFieldListSet(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueFieldList.set
    """
    def test_success(self):
        inst = _of_list_setup()
        # Call
        inst.set("down", ["there"])
        # Tests
        ntools.eq_(inst._labels["down"], ["there"])

    def test_failure(self):
        inst = _of_list_setup()
        # Call
        ntools.assert_raises(SCIONKeyError, inst.set, "oops", ["there"])


class TestOpaqueFieldListGetByIdx(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueFieldList.get_by_idx
    """
    def _check(self, idx, expected):
        inst = _of_list_setup()
        # Call
        ntools.eq_(inst.get_by_idx(idx), expected)

    def test(self):
        for idx, expected in (
            (0, "up0"),
            (2, "up2"),
            (3, "core0"),
        ):
            yield self._check, idx, expected

    def _check_bounds(self, index):
        inst = _of_list_setup()
        # Call
        ntools.assert_raises(SCIONIndexError, inst.get_by_idx, index)

    def test_bounds(self):
        for i in (-1, 4):
            yield self._check_bounds, i


class TestOpaqueFieldListGetByLabel(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueFieldList.get_by_label
    """
    def test_basic(self):
        inst = _of_list_setup()
        # Call
        ntools.eq_(inst.get_by_label("core"), ["core0"])

    def test_with_idx(self):
        inst = _of_list_setup()
        # Call
        ntools.eq_(inst.get_by_label("up", 2), "up2")

    def test_label_error(self):
        inst = _of_list_setup()
        # Call
        ntools.assert_raises(SCIONKeyError, inst.get_by_label, "nope")

    def test_idx_error(self):
        inst = _of_list_setup()
        # Call
        ntools.assert_raises(SCIONIndexError, inst.get_by_label, "core", 4)


class TestOpaqueFieldListGetLabelByIdx(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueFieldList.get_label_by_idx
    """
    def _check(self, idx, expected):
        inst = _of_list_setup()
        # Call
        ntools.eq_(inst.get_label_by_idx(idx), expected)

    def test(self):
        for idx, expected in (
            (0, "up"),
            (2, "up"),
            (3, "core"),
        ):
            yield self._check, idx, expected

    def _check_bounds(self, index):
        inst = _of_list_setup()
        # Call
        ntools.assert_raises(SCIONIndexError, inst.get_label_by_idx, index)

    def test_bounds(self):
        for i in (-1, 4):
            yield self._check_bounds, i


class TestOpaqueFieldListGetIdxByLabel(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueFieldList.get_idx_by_label
    """
    def _check(self, label, expected):
        inst = _of_list_setup()
        # Call
        ntools.eq_(inst.get_idx_by_label(label), expected)

    def test_with_label(self):
        for (label, expected) in (
            ("up", 0),
            ("core", 3)
        ):
            yield self._check, label, expected

    def _check_error(self, label):
        inst = _of_list_setup()
        # Call
        ntools.assert_raises(SCIONKeyError, inst.get_idx_by_label, label)

    def test_label_error(self):
        for label in ("nope", "down"):
            yield self._check_error, label


class TestOpaqueFieldListSwap(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueFieldList.swap
    """
    def test_basic(self):
        inst = _of_list_setup()
        # Call
        inst.swap("up", "core")
        # Tests
        ntools.eq_(inst._labels, {
            "up": ["core0"],
            "down": [],
            "core": ["up0", "up1", "up2"],
        })

    def test_one_empty(self):
        inst = _of_list_setup()
        # Call
        inst.swap("down", "core")
        # Tests
        ntools.eq_(inst._labels, {
            "up": ["up0", "up1", "up2"],
            "down": ["core0"],
            "core": [],
        })

    def test_label_error(self):
        inst = _of_list_setup()
        # Call
        ntools.assert_raises(SCIONKeyError, inst.swap, "up", "nope")


class TestOpaqueFieldListReverseLabel(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueFieldList.reverse_label
    """
    def test_basic(self):
        inst = _of_list_setup()
        # Call
        inst.reverse_label("up")
        # Tests
        ntools.eq_(inst._labels["up"], ["up2", "up1", "up0"])

    def test_label_error(self):
        inst = _of_list_setup()
        # Call
        ntools.assert_raises(SCIONKeyError, inst.reverse_label, "nope")


class TestOpaqueFieldListReverseUpFlag(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueFieldList.reverse_up_flag
    """
    def test_basic(self):
        inst = _of_list_setup()
        iof = create_mock(["up_flag"])
        iof.up_flag = True
        inst._labels["down"] = [iof]
        # Call
        inst.reverse_up_flag("down")
        # Tests
        ntools.assert_false(iof.up_flag)

    def test_empty(self):
        inst = _of_list_setup()
        # Call
        inst.reverse_up_flag("down")

    def test_label_error(self):
        inst = _of_list_setup()
        # Call
        ntools.assert_raises(SCIONKeyError, inst.reverse_up_flag, "nope")


class TestOpaqueFieldListPack(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueFieldList.pack
    """
    def test_basic(self):
        order = ["a", "b", "c", "d"]
        inst = OpaqueFieldList(order)
        ofs = []
        for i in range(5):
            of = create_mock(["pack"])
            of.pack.return_value = bytes([i])
            ofs.append(of)
        inst._labels = {
            "a": ofs[:2],
            "b": [],
            "c": [ofs[2]],
            "d": ofs[3:],
        }
        # Call
        ntools.eq_(inst.pack(), bytes(range(5)))
        # Tests
        for of in ofs:
            of.pack.assert_called_once_with()


class TestOpaqueFieldListCount(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueFieldList.count
    """
    def test_basic(self):
        inst = _of_list_setup()
        # Call
        ntools.eq_(inst.count("up"), 3)

    def test_label_error(self):
        inst = _of_list_setup()
        # Call
        ntools.assert_raises(SCIONKeyError, inst.count, "nope")


class TestOpaqueFieldListLen(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueFieldList.__len__
    """
    def test_basic(self):
        inst = _of_list_setup()
        # Call
        ntools.eq_(len(inst), 4)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
