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
import struct
from unittest.mock import patch, MagicMock, Mock

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.opaque_field import HopOpaqueField
from lib.packet.packet_base import HeaderBase
from lib.packet.pcb import (
    ADMarking,
    Marking,
    PathConstructionBeacon,
    PathSegment,
    PCBMarking,
    REV_TOKEN_LEN)
from lib.packet.scion import PacketType, SCIONHeader
from lib.packet.scion_addr import ISD_AD, SCIONAddr
from lib.defines import EXP_TIME_UNIT


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


class TestMarkingNe(object):
    """
    Unit test for lib.packet.pcb.Marking.__ne__
    """
    @patch("lib.packet.pcb.Marking.__eq__", autospec=True)
    def test_false(self, eq):
        marking = Marking()
        eq.return_value = True
        ntools.assert_false(marking != 123)
        eq.assert_called_once_with(marking, 123)

    @patch("lib.packet.pcb.Marking.__eq__", autospec=True)
    def test_true(self, eq):
        marking = Marking()
        eq.return_value = False
        ntools.assert_true(marking != 123)


class TestMarkingHash(object):
    """
    Unit test for lib.packet.pcb.Marking.__hash__
    """
    def test(self):
        marking = Marking()
        marking.raw = MagicMock()
        marking.raw.__hash__.return_value = 123
        ntools.eq_(hash(marking), 123)
        marking.raw.__hash__.assert_called_once_with()


class TestPCBMarkingInit(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.__init__
    """
    @patch("lib.packet.pcb.Marking.__init__", autospec=True)
    def test_basic(self, marking_init):
        pcbm = PCBMarking()
        marking_init.assert_called_once_with(pcbm)
        ntools.eq_(pcbm.isd_id, 0)
        ntools.eq_(pcbm.ad_id, 0)
        ntools.assert_is_none(pcbm.hof)
        ntools.eq_(pcbm.ig_rev_token, REV_TOKEN_LEN * b"\x00")

    @patch("lib.packet.pcb.PCBMarking.parse", autospec=True)
    def test_raw(self, parse):
        pcbm = PCBMarking('rawstring')
        parse.assert_called_once_with(pcbm, 'rawstring')


class TestPCBMarkingParse(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.parse
    """
    @patch("lib.packet.pcb.HopOpaqueField", autospec=True)
    @patch("lib.packet.pcb.ISD_AD", autospec=True)
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
        hop_of.assert_called_once_with(data[offset:offset + HopOpaqueField.LEN])
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
        ntools.assert_is_instance(pcbm, PCBMarking)
        ntools.eq_(pcbm.isd_id, 1)
        ntools.eq_(pcbm.ad_id, 2)
        ntools.eq_(pcbm.hof, 3)
        ntools.eq_(pcbm.ig_rev_token, 4)


class TestPCBMarkingPack(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.pack
    """
    @patch("lib.packet.pcb.ISD_AD", autospec=True)
    def test(self, isd_ad):
        pcbm = PCBMarking()
        pcbm.isd_id = 1
        pcbm.ad_id = 2
        pcbm.hof = MagicMock(spec_set=['pack'])
        pcbm.hof.pack = MagicMock(spec_set=[])
        pcbm.hof.pack.return_value = b'hof'
        pcbm.ig_rev_token = b'ig_rev_token'
        isd_ad.return_value = MagicMock(spec_set=['pack'])
        isd_ad.return_value.pack.return_value = b'(isd, ad)'
        packed = pcbm.pack()
        isd_ad.assert_called_once_with(1, 2)
        isd_ad.return_value.pack.assert_called_once_with()
        pcbm.hof.pack.assert_called_once_with()
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
    @patch("lib.packet.pcb.Marking.__init__", autospec=True)
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

    @patch("lib.packet.pcb.ADMarking.parse", autospec=True)
    def test_with_args(self, parse):
        ad_marking = ADMarking('data')
        parse.assert_called_once_with(ad_marking, 'data')


class TestADMarkingParse(object):
    """
    Unit test for lib.packet.pcb.ADMarking.parse
    """
    @patch("lib.packet.pcb.ADMarking._parse_peers", autospec=True)
    @patch("lib.packet.pcb.ADMarking._parse_pcbm", autospec=True)
    @patch("lib.packet.pcb.ADMarking._parse_metadata", autospec=True)
    def test(self, parse_metadata, parse_pcbm, parse_peers):
        ad_marking = ADMarking()
        # using a larger length as a buffer
        dlen = (PCBMarking.LEN + ADMarking.METADATA_LEN + REV_TOKEN_LEN) * 2
        data = bytes(range(dlen))
        parse_peers.return_value = PCBMarking.LEN
        ad_marking.parse(data)
        parse_metadata.assert_called_once_with(ad_marking,
                                               data[:ADMarking.METADATA_LEN])
        data = data[ADMarking.METADATA_LEN:]
        parse_pcbm.assert_called_once_with(ad_marking, data[:PCBMarking.LEN])
        data = data[PCBMarking.LEN:]
        parse_peers.assert_called_once_with(ad_marking, data)
        data = data[PCBMarking.LEN:]
        ntools.eq_(ad_marking.asd, data[:ad_marking.asd_len])
        data = data[ad_marking.asd_len:]
        ntools.eq_(ad_marking.eg_rev_token, data[:REV_TOKEN_LEN])
        ntools.eq_(ad_marking.sig, data[REV_TOKEN_LEN:])
        ntools.assert_true(ad_marking.parsed)

    def test_wrong_type(self):
        ad_marking = ADMarking()
        ntools.assert_raises(AssertionError, ad_marking.parse, 123)

    def test_bad_length(self):
        ad_marking = ADMarking()
        dlen = PCBMarking.LEN + ADMarking.METADATA_LEN + REV_TOKEN_LEN
        ad_marking.parse(bytes(range(dlen - 1)))
        ntools.assert_false(ad_marking.parsed)


class TestADMarkingParseMetadata(object):
    """
    Unit test for lib.packet.pcb.ADMarking._parse_metadata
    """
    def test(self):
        data = bytes.fromhex('0102 0304 0506 0708')
        ad_marking = ADMarking()
        ad_marking._parse_metadata(data)
        ntools.eq_(ad_marking.cert_ver, 0x0102)
        ntools.eq_(ad_marking.sig_len, 0x0304)
        ntools.eq_(ad_marking.asd_len, 0x0506)
        ntools.eq_(ad_marking.block_len, 0x0708)

    def test_bad_length(self):
        ad_marking = ADMarking()
        ntools.assert_raises(AssertionError, ad_marking._parse_metadata,
                             b'\x00' * (ad_marking.METADATA_LEN - 1))


class TestADMarkingParsePcbm(object):
    """
    Unit test for lib.packet.pcb.ADMarking._parse_pcbm
    """
    @patch("lib.packet.pcb.PCBMarking", autospec=True)
    def test(self, pcb_marking):
        data = b'\x00' * PCBMarking.LEN
        pcb_marking.LEN = PCBMarking.LEN
        pcb_marking.return_value = 'pcb_marking'
        ad_marking = ADMarking()
        ad_marking._parse_pcbm(data)
        pcb_marking.assert_called_once_with(data)
        ntools.eq_(ad_marking.pcbm, 'pcb_marking')

    def test_bad_length(self):
        ad_marking = ADMarking()
        ntools.assert_raises(AssertionError, ad_marking._parse_pcbm,
                             b'\x00' * (PCBMarking.LEN - 1))


class TestADMarkingParsePeers(object):
    """
    Unit test for lib.packet.pcb.ADMarking._parse_peers
    """
    @patch("lib.packet.pcb.PCBMarking", autospec=True)
    def test(self, pcb_marking):
        ad_marking = ADMarking()
        data = bytes(range(PCBMarking.LEN))
        pcb_marking.LEN = PCBMarking.LEN
        pcb_marking.return_value = 'pcb_marking'
        offset = ad_marking._parse_peers(data)
        ntools.eq_(ad_marking.pms, ['pcb_marking'])
        ntools.eq_(offset, PCBMarking.LEN)


class TestADMarkingFromValues(object):
    """
    Unit test for lib.packet.pcb.ADMarking.from_values
    """
    def test(self):
        pcbm = MagicMock()
        pms = [MagicMock(), MagicMock()]
        eg_rev_token = bytes(range(REV_TOKEN_LEN))
        sig = b'sig_bytes'
        asd = b'asd_bytes'
        ad_marking = ADMarking.from_values(pcbm, pms, eg_rev_token, sig, asd)
        ntools.assert_is_instance(ad_marking, ADMarking)
        ntools.eq_(ad_marking.block_len, (1 + len(pms)) * PCBMarking.LEN)
        ntools.eq_(ad_marking.pcbm, pcbm)
        ntools.eq_(ad_marking.pms, pms)
        ntools.eq_(ad_marking.sig, sig)
        ntools.eq_(ad_marking.sig_len, len(sig))
        ntools.eq_(ad_marking.asd, asd)
        ntools.eq_(ad_marking.asd_len, len(asd))
        ntools.eq_(ad_marking.eg_rev_token, eg_rev_token)

    def test_less_arg(self):
        ad_marking = ADMarking.from_values()
        ntools.eq_(ad_marking.block_len, PCBMarking.LEN)
        ntools.assert_is_none(ad_marking.pcbm)
        ntools.eq_(ad_marking.pms, [])
        ntools.eq_(ad_marking.sig, b'')
        ntools.eq_(ad_marking.sig_len, 0)
        ntools.eq_(ad_marking.asd, b'')
        ntools.eq_(ad_marking.asd_len, 0)
        ntools.eq_(ad_marking.eg_rev_token, REV_TOKEN_LEN * b'\x00')


class TestADMarkingPack(object):
    """
    Unit test for lib.packet.pcb.ADMarking.pack
    """
    def test(self):
        ad_marking = ADMarking()
        (ad_marking.cert_ver, ad_marking.sig_len, ad_marking.asd_len,
         ad_marking.block_len) = (1, 2, 3, 4)
        ad_marking.pcbm = Mock(spec_set=['pack'])
        ad_marking.pcbm.pack.return_value = b'packed_pcbm'
        pm = Mock(spec_set=['pack'])
        pm.pack.return_value = b'packed_pm'
        ad_marking.pms = [pm]
        ad_marking.asd = b'asd'
        ad_marking.eg_rev_token = b'eg_rev_token'
        ad_marking.sig = b'sig'
        ad_bytes = struct.pack("!HHHH", 1, 2, 3, 4) + b'packed_pcbm' + \
                   b'packed_pm' + b'asd' + b'eg_rev_token' + b'sig'
        ntools.eq_(ad_marking.pack(), ad_bytes)


class TestADMarkingRemoveSignature(object):
    """
    Unit test for lib.packet.pcb.ADMarking.remove_signature
    """
    def test(self):
        ad_marking = ADMarking()
        ad_marking.remove_signature()
        ntools.eq_(ad_marking.sig, b'')
        ntools.eq_(ad_marking.sig_len, 0)


class TestADMarkingRemoveAsd(object):
    """
    Unit test for lib.packet.pcb.ADMarking.remove_asd
    """
    def test(self):
        ad_marking = ADMarking()
        ad_marking.remove_asd()
        ntools.eq_(ad_marking.asd, b'')
        ntools.eq_(ad_marking.asd_len, 0)


class TestADMarkingEq(object):
    """
    Unit test for lib.packet.pcb.ADMarking.__eq__
    """
    def test_equal(self):
        ad_marking1 = ADMarking.from_values('pcbm', ['pms'], b'eg_rev_token',
                                            b'sig', b'asd')
        ad_marking2 = ADMarking.from_values('pcbm', ['pms'], b'eg_rev_token',
                                            b'sig', b'asd')
        ntools.eq_(ad_marking1, ad_marking2)

    def test_unequal(self):
        ad_marking1 = ADMarking.from_values('pcbm', ['pms'], b'eg_rev_token',
                                            b'sig1', b'asd')
        ad_marking2 = ADMarking.from_values('pcbm', ['pms'], b'eg_rev_token',
                                            b'sig2', b'asd')
        ntools.assert_not_equals(ad_marking1, ad_marking2)

    def test_unequal_type(self):
        ad_marking1 = ADMarking()
        ad_marking2 = 123
        ntools.assert_not_equals(ad_marking1, ad_marking2)


class TestPathSegmentInit(object):
    """
    Unit test for lib.packet.pcb.PathSegment.__init__
    """
    @patch("lib.packet.pcb.Marking.__init__", autospec=True)
    def test(self, init):
        path_segment = PathSegment()
        init.assert_called_once_with(path_segment)
        ntools.assert_is_none(path_segment.iof)
        ntools.eq_(path_segment.trc_ver, 0)
        ntools.eq_(path_segment.if_id, 0)
        ntools.eq_(path_segment.segment_id, REV_TOKEN_LEN * b"\x00")
        ntools.eq_(path_segment.ads, [])
        ntools.eq_(path_segment.min_exp_time, 2 ** 8 - 1)

    @patch("lib.packet.pcb.PathSegment.parse", autospec=True)
    def test_with_args(self, parse):
        path_segment = PathSegment('data')
        parse.assert_called_once_with(path_segment, 'data')


class TestPathSegmentParse(object):
    """
    Unit test for lib.packet.pcb.PathSegment.parse
    """
    def test(self):
        # TODO: refactor code
        pass


class TestPathSegmentPack(object):
    """
    Unit test for lib.packet.pcb.PathSegment.pack
    """
    def test(self):
        path_segment = PathSegment()
        path_segment.iof = Mock(spec_set=['pack'])
        path_segment.iof.pack.return_value = b'packed_iof'
        (path_segment.trc_ver, path_segment.if_id) = (1, 2)
        path_segment.segment_id = b'segment_id'
        ad_marking = Mock(spec_set=['pack'])
        ad_marking.pack.return_value = b'ad_marking'
        path_segment.ads = [ad_marking]
        pcb_bytes = b'packed_iof' + struct.pack("!IH", 1, 2) + b'segment_id' \
                    + b'ad_marking'
        ntools.eq_(path_segment.pack(), pcb_bytes)


class TestPathSegmentAddAd(object):
    """
    Unit test for lib.packet.pcb.PathSegment.add_ad
    """
    def test_higher_exp_time(self):
        path_segment = PathSegment()
        ad_marking = MagicMock(spec_set=['pcbm'])
        ad_marking.pcbm.hof.exp_time = path_segment.min_exp_time + 1
        path_segment.iof = MagicMock(spec_set=['hops'])
        path_segment.add_ad(ad_marking)
        ntools.assert_in(ad_marking, path_segment.ads)
        ntools.eq_(path_segment.iof.hops, len(path_segment.ads))

    def test_lower_exp_time(self):
        path_segment = PathSegment()
        ad_marking = MagicMock(spec_set=['pcbm'])
        ad_marking.pcbm.hof.exp_time = path_segment.min_exp_time - 1
        path_segment.iof = MagicMock(spec_set=['hops'])
        path_segment.add_ad(ad_marking)
        ntools.eq_(path_segment.min_exp_time, ad_marking.pcbm.hof.exp_time)


class TestPathSegmentRemoveSignatures(object):
    """
    Unit test for lib.packet.pcb.PathSegment.remove_signatures
    """
    def test(self):
        path_segment = PathSegment()
        path_segment.ads = [Mock(spec_set=['remove_signature']) for i in
                            range(3)]

        path_segment.remove_signatures()
        for ad in path_segment.ads:
            ad.remove_signature.assert_called_once_with()


class TestPathSegmentRemoveAsds(object):
    """
    Unit test for lib.packet.pcb.PathSegment.remove_asds
    """
    def test(self):
        path_segment = PathSegment()
        path_segment.ads = [Mock(spec_set=['remove_asd']) for i in
                            range(3)]
        path_segment.remove_asds()
        for ad in path_segment.ads:
            ad.remove_asd.assert_called_once_with()


class TestPathSegmentGetPath(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_path
    """
    def test(self):
        pass


class TestPathSegmentGetIsd(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_isd
    """
    def test(self):
        path_segment = PathSegment()
        path_segment.iof = Mock(spec_set=['isd_id'])
        ntools.eq_(path_segment.iof.isd_id, path_segment.get_isd())


class TestPathSegmentGetLastAdm(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_last_adm
    """
    def test_basic(self):
        path_segment = PathSegment()
        path_segment.ads = [Mock() for i in range(3)]
        ntools.eq_(path_segment.get_last_adm(), path_segment.ads[-1])

    def test_empty(self):
        path_segment = PathSegment()
        ntools.assert_is_none(path_segment.get_last_adm())


class TestPathSegmentGetLastPcbm(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_last_pcbm
    """
    def test_basic(self):
        path_segment = PathSegment()
        path_segment.ads = [Mock(spec_set=['pcbm']) for i in range(3)]
        ntools.eq_(path_segment.get_last_pcbm(), path_segment.ads[-1].pcbm)

    def test_empty(self):
        path_segment = PathSegment()
        ntools.assert_is_none(path_segment.get_last_pcbm())


class TestPathSegmentGetFirstPcbm(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_first_pcbm
    """
    def test_basic(self):
        path_segment = PathSegment()
        path_segment.ads = [Mock(spec_set=['pcbm']) for i in range(3)]
        ntools.eq_(path_segment.get_first_pcbm(), path_segment.ads[0].pcbm)

    def test_empty(self):
        path_segment = PathSegment()
        ntools.assert_is_none(path_segment.get_first_pcbm())


class TestPathSegmentCompareHops(object):
    """
    Unit test for lib.packet.pcb.PathSegment.compare_hops
    """
    def test_equal(self):
        path_segment = PathSegment()
        ads = [Mock(spec_set=['pcbm']) for i in range(3)]
        path_segment.ads = ads
        other = PathSegment()
        other.ads = ads
        ntools.assert_true(path_segment.compare_hops(other))

    def test_unequal(self):
        path_segment = PathSegment()
        ads = [Mock(spec_set=['pcbm']) for i in range(3)]
        path_segment.ads = ads
        other = PathSegment()
        other.ads = ads[:2]
        ntools.assert_false(path_segment.compare_hops(other))

    def test_wrong_type(self):
        path_segment = PathSegment()
        ntools.assert_false(path_segment.compare_hops(123))


class TestPathSegmentGetHopsHash(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_hops_hash
    """
    def test(self):
        pass


class TestPathSegmentGetNPeerLinks(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_n_peer_links
    """
    def test(self):
        ads = [MagicMock(spec_set=['pms']) for i in range(3)]
        ads[0].pms.__len__.return_value = 10
        ads[1].pms.__len__.return_value = 20
        ads[2].pms.__len__.return_value = 30
        path_segment = PathSegment()
        path_segment.ads = ads
        ntools.eq_(path_segment.get_n_peer_links(), 60)


class TestPathSegmentGetNHops(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_n_hops
    """
    def test(self):
        ads = MagicMock()
        ads.__len__.return_value = 123
        path_segment = PathSegment()
        path_segment.ads = ads
        ntools.eq_(path_segment.get_n_hops(), 123)


class TestPathSegmentGetTimestamp(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_timestamp
    """
    def test(self):
        iof = Mock(spec_set=['timestamp'])
        path_segment = PathSegment()
        path_segment.iof = iof
        ntools.eq_(path_segment.get_timestamp(), iof.timestamp)


class TestPathSegmentSetTimestamp(object):
    """
    Unit test for lib.packet.pcb.PathSegment.set_timestamp
    """
    def test_failure(self):
        path_segment = PathSegment()
        ntools.assert_raises(AssertionError, path_segment.set_timestamp,
                             2 ** 32)

    def test_success(self):
        path_segment = PathSegment()
        path_segment.iof = Mock(spec_set=['timestamp'])
        path_segment.set_timestamp(123)
        ntools.eq_(path_segment.iof.timestamp, 123)


class TestPathSegmentGetExpirationTime(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_expiration_time
    """
    def test(self):
        path_segment = PathSegment()
        path_segment.iof = Mock(spec_set=['timestamp'])
        path_segment.iof.timestamp = 123
        path_segment.min_exp_time = 456
        ntools.eq_(path_segment.get_expiration_time(),
                   123 + int(456 * EXP_TIME_UNIT))


class TestPathSegmentGetAllIftokens(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_all_iftokens
    """
    def test(self):
        path_segment = PathSegment()
        ads = [Mock(spec_set=['pcbm', 'eg_rev_token', 'pms']) for i in range(2)]
        ads[0].pcbm.ig_rev_token, ads[1].pcbm.ig_rev_token = 'ig_rev_token0', \
                                                             'ig_rev_token1'
        ads[0].eg_rev_token, ads[1].eg_rev_token = 'eg_rev_token0', \
                                                   'eg_rev_token1'
        ads[0].pms, ads[1].pms = [Mock(spec_set=['ig_rev_token'])], \
                                [Mock(spec_set=['ig_rev_token'])]
        ads[0].pms[0].ig_rev_token, ads[1].pms[0].ig_rev_token = \
            'pm_ig_rev_token0', 'pm_ig_rev_token1'
        path_segment.ads = ads
        tokens = ['ig_rev_token0', 'eg_rev_token0', 'pm_ig_rev_token0',
                  'ig_rev_token1', 'eg_rev_token1', 'pm_ig_rev_token1']
        ntools.eq_(path_segment.get_all_iftokens(), tokens)


class TestPathSegmentDeserialize(object):
    """
    Unit test for lib.packet.pcb.PathSegment.deserialize
    """
    def test(self):
        pass


class TestPathSegmentSerialize(object):
    """
    Unit test for lib.packet.pcb.PathSegment.serialize
    """
    def test(self):
        pcbs = [Mock(spec_set=['pack']) for i in range(3)]
        (pcbs[0].pack.return_value, pcbs[1].pack.return_value,
         pcbs[2].pack.return_value) = (b'data0', b'data1', b'data2')
        ntools.eq_(PathSegment.serialize(pcbs), b''.join([b'data0', b'data1',
                                                          b'data2']))


class TestPathSegmentEq(object):
    """
    Unit test for lib.packet.pcb.PathSegment.__eq__
    """
    def test_equal(self):
        path_seg1 = PathSegment()
        path_seg2 = PathSegment()
        (path_seg1.iof, path_seg1.trc_ver, path_seg1.ads) = (1, 2, 3)
        (path_seg2.iof, path_seg2.trc_ver, path_seg2.ads) = (1, 2, 3)
        ntools.eq_(path_seg1, path_seg2)

    def test_unequal(self):
        path_seg1 = PathSegment()
        path_seg2 = PathSegment()
        (path_seg1.iof, path_seg1.trc_ver, path_seg1.ads) = (1, 2, 3)
        (path_seg2.iof, path_seg2.trc_ver, path_seg2.ads) = (1, 2, 4)
        ntools.assert_not_equals(path_seg1, path_seg2)

    def test_unequal_type(self):
        path_seg1 = PathSegment()
        path_seg2 = 123
        ntools.assert_not_equals(path_seg1, path_seg2)


class TestPathConstructionBeaconInit(object):
    """
    Unit test for lib.packet.pcb.PathConstructionBeacon.__init__
    """
    @patch("lib.packet.pcb.SCIONPacket.__init__", autospec=True)
    def test(self, init):
        pcb = PathConstructionBeacon()
        init.assert_called_once_with(pcb)
        ntools.assert_is_none(pcb.pcb)

    @patch("lib.packet.pcb.PathConstructionBeacon.parse", autospec=True)
    def test_with_args(self, parse):
        pcb = PathConstructionBeacon('data')
        parse.assert_called_once_with(pcb, 'data')


class TestPathConstructionBeaconParse(object):
    """
    Unit test for lib.packet.pcb.PathConstructionBeacon.parse
    """
    @patch("lib.packet.pcb.PathSegment", autospec=True)
    @patch("lib.packet.pcb.SCIONPacket.parse", autospec=True)
    def test(self, parse, path_segment):
        pcb = PathConstructionBeacon()
        pcb._payload = Mock()
        path_segment.return_value = 'path_seg'
        pcb.parse('data')
        parse.assert_called_once_with(pcb, 'data')
        path_segment.assert_called_once_with(pcb.payload)
        ntools.eq_(pcb.pcb, 'path_seg')


class TestPathConstructionBeaconFromValues(object):
    """
    Unit test for lib.packet.pcb.PathConstructionBeacon.from_values
    """
    @patch("lib.packet.pcb.SCIONHeader.from_values",
           spec=SCIONHeader.from_values)
    @patch("lib.packet.pcb.SCIONAddr.from_values", spec=SCIONAddr.from_values)
    def test(self, scion_addr, scion_header):
        src_isd_ad = Mock(spec_set=['isd', 'ad'])
        dst, pcb = Mock(), Mock()
        scion_addr.return_value = 'src'
        scion_header.return_value = Mock(spec=HeaderBase)
        beacon = PathConstructionBeacon.from_values(src_isd_ad, dst, pcb)
        ntools.assert_is_instance(beacon, PathConstructionBeacon)
        scion_addr.assert_called_once_with(src_isd_ad.isd, src_isd_ad.ad,
                                           PacketType.BEACON)
        scion_header.assert_called_once_with('src', dst)
        ntools.eq_(beacon.pcb, pcb)
        ntools.eq_(beacon.hdr, scion_header.return_value)


class TestPathConstructionBeaconPack(object):
    """
    Unit test for lib.packet.pcb.PathConstructionBeacon.pack
    """
    @patch("lib.packet.pcb.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.pcb.SCIONPacket.pack", autospec=True)
    def test(self, pack, set_payload):
        pcb = PathConstructionBeacon()
        pcb.pcb = Mock(spec_set=['pack'])
        pcb.pcb.pack.return_value = b'payload'
        pack.return_value = b'packed'
        ntools.eq_(pcb.pack(), b'packed')
        pack.assert_called_once_with(pcb)
        set_payload.assert_called_once_with(pcb, b'payload')


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
