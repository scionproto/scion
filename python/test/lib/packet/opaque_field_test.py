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
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONIndexError, SCIONKeyError
from lib.packet.opaque_field import HopOpaqueField, OpaqueFieldList
from test.testcommon import create_mock, create_mock_full


class TestHopOpaqueFieldParse(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField._parse
    """
    @patch("lib.packet.opaque_field.Raw", autospec=True)
    def test(self, raw):
        inst = HopOpaqueField()
        inst._parse_flags = create_mock()
        data = create_mock(["pop"])
        data.pop.side_effect = map(bytes.fromhex, ('0e 2a', '0a0b0c', '012345'))
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.LEN)
        ntools.eq_(inst.exp_time, 0x2a)
        inst._parse_flags.assert_called_once_with(0x0e)
        ntools.eq_(inst.ingress_if, 0x0a0)
        ntools.eq_(inst.egress_if, 0xb0c)
        ntools.eq_(inst.mac, bytes.fromhex('012345'))


class TestHopOpaqueFieldPack(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.pack
    """
    def test_basic(self):
        inst = HopOpaqueField()
        inst._pack_flags = create_mock()
        inst._pack_flags.return_value = 0x0e
        inst.exp_time = 0x2a
        inst.ingress_if = 0x0a0
        inst.egress_if = 0xb0c
        inst.mac = bytes.fromhex('012345')
        expected = bytes.fromhex('0e 2a 0a0b0c 012345')
        # Call
        ntools.eq_(inst.pack(), expected)

    def test_mac(self):
        inst = HopOpaqueField()
        inst._pack_flags = create_mock()
        inst._pack_flags.return_value = 0x0e
        inst.exp_time = 0x2a
        inst.ingress_if = 0x0a0
        inst.egress_if = 0xb0c
        inst.mac = bytes.fromhex('012345')
        expected = bytes.fromhex('00 2a 0a0b0c')
        # Call
        ntools.eq_(inst.pack(mac=True), expected)


class TestHopOpaqueFieldCalcMac(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.calc_mac
    """
    @patch("lib.packet.opaque_field.mac", autospec=True)
    def test_no_prev(self, mac):
        inst = HopOpaqueField()
        inst.pack = create_mock()
        pack_mac = bytes.fromhex('02 2a0a 0b0c')
        inst.pack.return_value = pack_mac
        ts = 0x01020304
        expected = b"".join([
            ts.to_bytes(4, "big"), pack_mac, bytes(7),
        ])
        mac.return_value = "mac_data"
        # Call
        ntools.eq_(inst.calc_mac("key", ts), "mac")
        # Tests
        inst.pack.assert_called_once_with(mac=True)
        mac.assert_called_once_with("key", expected)

    @patch("lib.packet.opaque_field.mac", autospec=True)
    def test_prev(self, mac):
        inst = HopOpaqueField()
        inst.pack = create_mock()
        pack_mac = bytes.fromhex('02 2a0a 0b0c')
        inst.pack.return_value = pack_mac
        prev_pack_mac = bytes.fromhex('10 1112 1314')
        prev = create_mock_full({"pack()": prev_pack_mac})
        ts = 0x01020304
        expected = b"".join([
            ts.to_bytes(4, "big"), pack_mac, prev_pack_mac[1:],
        ])
        # Call
        inst.calc_mac("key", ts, prev)
        # Tests
        prev.pack.assert_called_once_with()
        mac.assert_called_once_with("key", expected)


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


class TestOpaqueFieldListReverseConsDirFlag(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueFieldList.reverse_cons_dir_flag
    """
    def test_basic(self):
        inst = _of_list_setup()
        iof = create_mock(["cons_dir_flag"])
        iof.cons_dir_flag = True
        inst._labels["down"] = [iof]
        # Call
        inst.reverse_cons_dir_flag("down")
        # Tests
        ntools.assert_false(iof.cons_dir_flag)

    def test_empty(self):
        inst = _of_list_setup()
        # Call
        inst.reverse_cons_dir_flag("down")

    def test_label_error(self):
        inst = _of_list_setup()
        # Call
        ntools.assert_raises(SCIONKeyError, inst.reverse_cons_dir_flag, "nope")


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
