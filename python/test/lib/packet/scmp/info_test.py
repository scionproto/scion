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
:mod:`lib_packet_scmp_info_test` --- lib.packet.scmp.info unit tests
==================================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.scmp.info import (
    SCMPInfoGeneric,
    SCMPInfoPathOffsets,
    SCMPInfoString,
)
from test.testcommon import create_mock


class TestSCMPInfoStringParse(object):
    """
    Unit tests for lib.packet.scmp.info.SCMPInfoString._parse
    """
    @patch("lib.packet.scmp.info.Raw", autospec=True)
    def test(self, raw):
        inst = SCMPInfoString()
        inst._calc_len = create_mock()
        inst._calc_fmt = create_mock()
        inst._calc_fmt.return_value = "!H7s"
        input_ = bytes.fromhex("1234") + b"testing"
        data = create_mock(["pop"])
        data.pop.return_value = input_
        raw.return_value = data
        # Call
        inst._parse(input_)
        # Tests
        inst._calc_len.assert_called_once_with(0x1234)
        raw.assert_called_once_with(
            input_, inst.NAME, inst._calc_len.return_value)
        inst._calc_fmt.assert_called_once_with(0x1234)
        ntools.eq_(inst.val, b"testing")


class TestSCMPInfoStringPack(object):
    """
    Unit tests for lib.packet.scmp.info.SCMPInfoString.pack
    """
    def test(self):
        inst = SCMPInfoString()
        inst.val = bytes(range(5))
        inst._calc_fmt = create_mock()
        inst._calc_fmt.return_value = "!B5s"
        expected = bytes.fromhex("05 0001020304")
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        inst._calc_fmt.assert_called_once_with(5)


class TestSCMPInfoStringCalcFmt(object):
    """
    Unit tests for lib.packet.scmp.info.SCMPInfoString._calc_fmt
    """
    def _check(self, vlen, expected):
        inst = SCMPInfoString()
        # Call
        ntools.eq_(inst._calc_fmt(vlen), expected)

    def test(self):
        for vlen, fmt in (
            (1, "!H1s5x"), (5, "!H5s1x"), (6, "!H6s0x"), (7, "!H7s7x"),
            (13, "!H13s1x"), (14, "!H14s0x"), (15, "!H15s7x"),
        ):
            yield self._check, vlen, fmt


class SCMPInfoGenericTest(SCMPInfoGeneric):
    STRUCT_FMT = "BB"
    ATTRIBS = ["foo", "bar"]

    def from_pkt(self):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError


class TestSCMPInfoGenericInit(object):
    """
    Unit tests for lib.packet.scmp.info.SCMPInfoGeneric.__init__
    """
    @patch("lib.packet.scmp.info.SCMPInfoGeneric._set_vals", autospec=True)
    def test(self, set_vals):
        # Call
        inst = SCMPInfoGenericTest()
        # Tests
        set_vals.assert_called_once_with(inst, [None, None])


class TestSCMPInfoGenericParse(object):
    """
    Unit tests for lib.packet.scmp.info.SCMPInfoGeneric._parse
    """
    @patch("lib.packet.scmp.info.Raw", autospec=True)
    def test(self, raw):
        inst = SCMPInfoGenericTest()
        inst._set_vals = create_mock()
        data = create_mock(["pop"])
        data.pop.return_value = bytes([13, 47])
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, len_=inst.LEN)
        inst._set_vals.assert_called_once_with((13, 47))


class TestSCMPInfoGenericPack(object):
    """
    Unit tests for lib.packet.scmp.info.SCMPInfoGeneric.pack
    """
    def test(self):
        inst = SCMPInfoGenericTest()
        inst._get_vals = create_mock()
        inst._get_vals.return_value = 13, 47
        expected = bytes([13, 47])
        # Call
        ntools.eq_(inst.pack(), expected)


class TestSCMPInfoGenericSetVals(object):
    """
    Unit tests for lib.packet.scmp.info.SCMPInfoGeneric._set_vals
    """
    def test(self):
        inst = SCMPInfoGenericTest()
        # Call
        inst._set_vals((13, 47))
        # Tests
        ntools.eq_(inst.foo, 13)
        ntools.eq_(inst.bar, 47)


class TestSCMPInfoPathOffsetsFromPkt(object):
    """
    Unit tests for lib.packet.scmp.info.SCMPInfoPathOffsets.from_pkt
    """
    @patch("lib.packet.scmp.info.SCMPInfoPathOffsets._set_vals", autospec=True)
    @patch("lib.packet.scmp.info.SCMPInfoPathOffsets._calc_offsets",
           autospec=True)
    @patch("lib.packet.scmp.info.SCMPInfoPathOffsets.__init__", autospec=True,
           return_value=None)
    def test(self, init, calc_off, set_vals):
        calc_off.return_value = "iof", "hof"
        # Call
        inst = SCMPInfoPathOffsets.from_pkt("pkt", 33, "ingress")
        # Tests
        calc_off.assert_called_once_with(inst, "pkt")
        set_vals.assert_called_once_with(inst, ("iof", "hof", 33, "ingress"))


class TestSCMPInfoPathOffsetsCalcOffsets(object):
    """
    Unit tests for lib.packet.scmp.info.SCMPInfoPathOffsets._calc_offsets
    """
    def test(self):
        inst = SCMPInfoPathOffsets()
        pkt = create_mock(["cmn_hdr"])
        pkt.cmn_hdr = create_mock(["__len__", "get_of_idxs"])
        pkt.cmn_hdr.get_of_idxs.return_value = 3, 5
        # Call
        ntools.eq_(inst._calc_offsets(pkt), (3, 5))

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
