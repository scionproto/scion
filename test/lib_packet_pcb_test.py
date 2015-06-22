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
:mod:`lib_packet_pcb_test` --- lib.packet.pcb unit tests
========================================================
"""
# Stdlib
from unittest.mock import patch, MagicMock

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.opaque_field import HopOpaqueField
from lib.packet.pcb import (
    ADMarking,
    Marking,
    PCBMarking,
    REV_TOKEN_LEN)
from lib.packet.scion_addr import ISD_AD


class TestMarkingInit(object):
    """
    Unit test for lib.packet.pcb.Marking.__init__
    """
    def test(self):
        marking = Marking()
        ntools.assert_false(marking.parsed)
        ntools.assert_is_none(marking.raw)


class TestMarkingEq(object):
    """
    Unit test for lib.packet.pcb.Marking.__eq__
    """
    def test_same_type_equal(self):
        marking1 = Marking()
        marking2 = Marking()
        marking1.raw = 'rawstring'
        marking2.raw = 'rawstring'
        ntools.eq_(marking1, marking2)

    def test_same_type_unequal(self):
        marking1 = Marking()
        marking2 = Marking()
        marking1.raw = 'rawstring1'
        marking2.raw = 'rawstring2'
        ntools.assert_not_equal(marking1, marking2)

    def test_diff_type(self):
        marking1 = Marking()
        marking2 = 123
        ntools.assert_not_equals(marking1, marking2)


class TestPCBMarkingInit(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.__init__
    """
    @patch("lib.packet.pcb.Marking.__init__")
    def test_basic(self, marking_init):
        pcbm = PCBMarking()
        marking_init.assert_called_once_with(pcbm)
        ntools.eq_(pcbm.isd_id, 0)
        ntools.eq_(pcbm.ad_id, 0)
        ntools.assert_is_none(pcbm.hof)
        ntools.eq_(pcbm.ig_rev_token, REV_TOKEN_LEN * b"\x00")

    @patch("lib.packet.pcb.PCBMarking.parse")
    def test_raw(self, parse):
        PCBMarking('rawstring')
        parse.assert_called_once_with('rawstring')


class TestPCBMarkingParse(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.parse
    """
    @patch("lib.packet.pcb.HopOpaqueField")
    @patch("lib.packet.pcb.ISD_AD")
    def test(self, isd_ad, hop_of):
        pcbm = PCBMarking()
        data = bytes(range(PCBMarking.LEN))
        isd_ad.from_raw.return_value = (12, 34)
        isd_ad.LEN = ISD_AD.LEN
        hop_of.return_value = 'hop_of'
        hop_of.LEN = HopOpaqueField.LEN
        pcbm.parse(data)
        ntools.eq_(pcbm.raw, data)
        isd_ad.from_raw.assert_called_once_with(data[:ISD_AD.LEN])
        ntools.eq_(pcbm.isd_id, 12)
        ntools.eq_(pcbm.ad_id, 34)
        offset = ISD_AD.LEN
        hop_of.assert_called_once_with(data[ISD_AD.LEN:ISD_AD.LEN +
                                            HopOpaqueField.LEN])
        ntools.eq_(pcbm.hof, 'hop_of')
        offset += HopOpaqueField.LEN
        ntools.eq_(pcbm.ig_rev_token, data[offset:offset + REV_TOKEN_LEN])
        ntools.assert_true(pcbm.parsed)

    def test_wrong_type(self):
        pcbm = PCBMarking()
        ntools.assert_raises(AssertionError, pcbm.parse, 123)

    def test_bad_length(self):
        pcbm = PCBMarking()
        pcbm.parse(bytes(range(PCBMarking.LEN - 1)))
        ntools.assert_false(pcbm.parsed)


class TestPCBMarkingFromValues(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.from_values
    """
    def test(self):
        pcbm = PCBMarking.from_values(1, 2, 3, 4)
        ntools.eq_(pcbm.isd_id, 1)
        ntools.eq_(pcbm.ad_id, 2)
        ntools.eq_(pcbm.hof, 3)
        ntools.eq_(pcbm.ig_rev_token, 4)


class TestPCBMarkingPack(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.pack
    """
    @patch("lib.packet.pcb.ISD_AD")
    def test(self, isd_ad):
        pcbm = PCBMarking()
        pcbm.isd_id = 1
        pcbm.ad_id = 2
        pcbm.hof = MagicMock(spec=['pack'])
        pcbm.hof.pack.return_value = b'hof'
        pcbm.ig_rev_token = b'ig_rev_token'
        isd_ad.return_value = MagicMock(spec=['pack'])
        isd_ad.return_value.pack.return_value = b'(isd, ad)'
        isd_ad.pack.return_value = b'(isd, ad)'
        packed = pcbm.pack()
        isd_ad.assert_called_once_with(1, 2)
        isd_ad.pack.assert_called_once()
        pcbm.hof.pack.assert_called_once()
        ntools.eq_(packed, b'(isd, ad)' + b'hof' + b'ig_rev_token')


class TestPCBMarkingEq(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.__eq__
    """
    def test_same_type_equal(self):
        pcbm1 = PCBMarking.from_values(1, 2, 3, 4)
        pcbm2 = PCBMarking.from_values(1, 2, 3, 4)
        ntools.eq_(pcbm1, pcbm2)

    def test_same_type_unequal(self):
        pcbm1 = PCBMarking.from_values(1, 2, 3, 4)
        pcbm2 = PCBMarking.from_values(5, 6, 3, 4)
        ntools.assert_not_equals(pcbm1, pcbm2)

    def test_diff_type(self):
        pcbm1 = PCBMarking()
        pcbm2 = 123
        ntools.assert_not_equals(pcbm1, pcbm2)


class TestADMarkingInit(object):
    """
    Unit test for lib.packet.pcb.ADMarking.__init__
    """
    @patch("lib.packet.pcb.Marking.__init__")
    def test_no_args(self, marking_init):
        ad_marking = ADMarking()
        marking_init.assert_called_once_with(ad_marking)
        ntools.assert_is_none(ad_marking.pcbm)
        ntools.eq_(ad_marking.pms, [])
        ntools.eq_(ad_marking.sig, b'')
        ntools.eq_(ad_marking.asd, b'')
        ntools.eq_(ad_marking.eg_rev_token, REV_TOKEN_LEN * b"\x00")
        ntools.eq_(ad_marking.cert_ver, 0)
        ntools.eq_(ad_marking.sig_len, 0)
        ntools.eq_(ad_marking.asd_len, 0)
        ntools.eq_(ad_marking.block_len, 0)

    @patch("lib.packet.pcb.ADMarking.parse")
    def test_with_args(self, parse):
        ADMarking('data')
        parse.assert_called_once_with('data')


class TestADMarkingParse(object):
    """
    Unit test for lib.packet.pcb.ADMarking.parse
    """
    def test(self):
        pass

    def test_wrong_type(self):
        ad_marking = ADMarking()
        ntools.assert_raises(AssertionError, ad_marking.parse, 123)

    def test_bad_length(self):
        ad_marking = ADMarking()
        dlen = PCBMarking.LEN + ADMarking.METADATA_LEN + REV_TOKEN_LEN
        ad_marking.parse(bytes(range(dlen - 1)))
        ntools.assert_false(ad_marking.parsed)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
