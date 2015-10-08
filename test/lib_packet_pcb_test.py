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
from unittest.mock import MagicMock, patch, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.path import CorePath
from lib.packet.pcb import (
    ADMarking,
    PathSegment,
    PCBMarking,
    REV_TOKEN_LEN
)
from lib.defines import EXP_TIME_UNIT
from test.testcommon import assert_these_calls, create_mock


class TestPCBMarkingInit(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.__init__
    """
    @patch("lib.packet.pcb.PCBMarking._parse", autospec=True)
    @patch("lib.packet.pcb.MarkingBase.__init__", autospec=True)
    def test_basic(self, super_init, parse):
        inst = PCBMarking()
        # Tests
        super_init.assert_called_once_with()
        ntools.eq_(inst.isd_id, 0)
        ntools.eq_(inst.ad_id, 0)
        ntools.assert_is_none(inst.hof)
        ntools.eq_(inst.ig_rev_token, bytes(REV_TOKEN_LEN))

    @patch("lib.packet.pcb.PCBMarking._parse", autospec=True)
    @patch("lib.packet.pcb.MarkingBase.__init__", autospec=True)
    def test_raw(self, super_init, parse):
        inst = PCBMarking('data')
        # Tests
        parse.assert_called_once_with(inst, 'data')


class TestPCBMarkingFromValues(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.from_values
    """
    def test(self):
        inst = PCBMarking.from_values(1, 2, 3, 4)
        # Tests
        ntools.assert_is_instance(inst, PCBMarking)
        ntools.eq_(inst.isd_id, 1)
        ntools.eq_(inst.ad_id, 2)
        ntools.eq_(inst.hof, 3)
        ntools.eq_(inst.ig_rev_token, 4)


class TestPCBMarkingParse(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.parse
    """
    @patch("lib.packet.pcb.HopOpaqueField", autospec=True)
    @patch("lib.packet.pcb.ISD_AD.from_raw", new_callable=create_mock)
    @patch("lib.packet.pcb.Raw", autospec=True)
    def test(self, raw, isd_ad, hof):
        inst = PCBMarking()
        data = create_mock(["pop"])
        data.pop.side_effect = "pop isd_ad", "pop hof", "pop rev tkn"
        raw.return_value = data
        isd_ad.return_value = "isd", "ad"
        hof.return_value = 'hof'
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "PCBMarking", inst.LEN)
        isd_ad.assert_called_once_with("pop isd_ad")
        ntools.eq_(inst.isd_id, "isd")
        ntools.eq_(inst.ad_id, "ad")
        hof.assert_called_once_with("pop hof")
        ntools.eq_(inst.hof, 'hof')
        ntools.eq_(inst.ig_rev_token, "pop rev tkn")


class TestPCBMarkingPack(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.pack
    """
    @patch("lib.packet.pcb.PCBMarking.__len__", autospec=True)
    @patch("lib.packet.pcb.ISD_AD", autospec=True)
    def test(self, isd_ad, len_):
        inst = PCBMarking()
        inst.isd_id = "isd"
        inst.ad_id = "ad"
        inst.ig_rev_token = b'ig_rev_token'
        isd_ad_obj = create_mock(["pack"])
        isd_ad_obj.pack.return_value = b"isd ad"
        isd_ad.return_value = isd_ad_obj
        inst.hof = create_mock(['pack'])
        inst.hof.pack.return_value = b'hof'
        expected = b'isd ad' b'hof' b'ig_rev_token'
        len_.return_value = len(expected)
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        isd_ad.assert_called_once_with("isd", "ad")


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
    @patch("lib.packet.pcb.ADMarking._parse", autospec=True)
    @patch("lib.packet.pcb.MarkingBase.__init__", autospec=True)
    def test_no_args(self, super_init, parse):
        inst = ADMarking()
        # Tests
        super_init.assert_called_once_with()
        ntools.assert_is_none(inst.pcbm)
        ntools.eq_(inst.pms, [])
        ntools.eq_(inst.sig, b'')
        ntools.eq_(inst.ext, [])
        ntools.eq_(inst.eg_rev_token, bytes(REV_TOKEN_LEN))
        ntools.eq_(inst.cert_ver, 0)
        ntools.eq_(inst.block_len, 0)
        ntools.assert_false(parse.called)

    @patch("lib.packet.pcb.ADMarking._parse", autospec=True)
    def test_with_args(self, parse):
        inst = ADMarking('data')
        # Tests
        parse.assert_called_once_with(inst, 'data')


class TestADMarkingFromValues(object):
    """
    Unit test for lib.packet.pcb.ADMarking.from_values
    """
    def test_full(self):
        pcbm = create_mock()
        pms = ['pms0', 'pms1']
        eg_rev_token = bytes(range(REV_TOKEN_LEN))
        sig = b'sig_bytes'
        ext = ['ext1', 'ext22']
        # Call
        inst = ADMarking.from_values(pcbm, pms, eg_rev_token, sig, ext)
        # Tests
        ntools.assert_is_instance(inst, ADMarking)
        ntools.eq_(inst.pcbm, pcbm)
        ntools.eq_(inst.pms, pms)
        ntools.eq_(inst.block_len, 3 * PCBMarking.LEN)
        ntools.eq_(inst.sig, sig)
        ntools.eq_(inst.ext, ext)
        ntools.eq_(inst.eg_rev_token, eg_rev_token)

    def test_min(self):
        inst = ADMarking.from_values()
        ntools.assert_is_none(inst.pcbm)
        ntools.eq_(inst.pms, [])
        ntools.eq_(inst.block_len, PCBMarking.LEN)
        ntools.eq_(inst.sig, b'')
        ntools.eq_(inst.ext, [])
        ntools.eq_(inst.eg_rev_token, bytes(REV_TOKEN_LEN))


class TestADMarkingParse(object):
    """
    Unit test for lib.packet.pcb.ADMarking._parse
    """
    @patch("lib.packet.pcb.ADMarking._parse_ext", autospec=True)
    @patch("lib.packet.pcb.ADMarking._parse_peers", autospec=True)
    @patch("lib.packet.pcb.PCBMarking", autospec=True)
    @patch("lib.packet.pcb.Raw", autospec=True)
    def test(self, raw, pcb_marking, parse_peers, parse_ext):
        inst = ADMarking()
        data = create_mock(["pop"])
        data.pop.side_effect = (
            bytes(range(ADMarking.METADATA_LEN)),
            "pop pcbm", "pop rev tkn", "pop sig")
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "ADMarking", inst.MIN_LEN,
                                    min_=True)
        ntools.eq_(inst.cert_ver, 0x0001)
        ntools.eq_(inst.block_len, 0x0607)
        pcb_marking.assert_called_once_with("pop pcbm")
        ntools.eq_(inst.pcbm, pcb_marking.return_value)
        parse_peers.assert_called_once_with(inst, data, 0x0203, 0x0405)
        parse_ext.assert_called_once_with(inst, data, 0x0203)
        ntools.eq_(inst.eg_rev_token, "pop rev tkn")
        ntools.eq_(inst.sig, "pop sig")


class TestADMarkingParsePeers(object):
    """
    Unit test for lib.packet.pcb.ADMarking._parse_peers
    """
    @patch("lib.packet.pcb.PCBMarking", autospec=True)
    def test(self, pcb_marking):
        inst = ADMarking()
        data = create_mock(["__len__", "pop"])
        data.__len__.side_effect = [REV_TOKEN_LEN+2, REV_TOKEN_LEN+1, 0]
        data.pop.side_effect = ("pop pcbm0", "pop pcbm1")
        pcb_marking.side_effect = ['data0', 'data1']
        # Call
        inst._parse_peers(data, 0, 0)
        # Tests
        pcb_marking.assert_has_calls([call('pop pcbm0'), call('pop pcbm1')])
        ntools.eq_(inst.pms, ['data0', 'data1'])


class TestADMarkingParseExt(object):
    """
    Unit test for lib.packet.pcb.ADMarking._parse_ext
    """
    @patch("lib.packet.pcb.PCB_EXTENSION_MAP", new_callable=dict)
    def test(self, ext_map):
        inst = ADMarking()
        data = create_mock(["__len__", "pop"])
        data.__len__.side_effect = [
            REV_TOKEN_LEN+3, REV_TOKEN_LEN+2, REV_TOKEN_LEN+1, 0]
        data.pop.side_effect = range(9)
        constr0 = create_mock()
        constr1 = create_mock()
        ext_map[0] = constr0
        ext_map[6] = constr1
        # Call
        inst._parse_ext(data, 0)
        # Tests
        constr0.assert_called_once_with(2)
        constr1.assert_called_once_with(8)
        ntools.eq_(inst.ext, [constr0.return_value, constr1.return_value])


class TestADMarkingPack(object):
    """
    Unit test for lib.packet.pcb.ADMarking.pack
    """
    @patch("lib.packet.pcb.ADMarking.__len__", autospec=True)
    def test(self, len_):
        inst = ADMarking()
        (inst.cert_ver, sig_len, ext_len,
         inst.block_len) = range(4)
        inst.pcbm = create_mock(['pack'])
        inst.pcbm.pack.return_value = b'packed_pcbm'
        for i in range(2):
            pm = create_mock(['pack'])
            pm.pack.return_value = bytes('packed_pm%d' % i, "ascii")
            inst.pms.append(pm)
        inst._pack_ext = create_mock()
        inst._pack_ext.return_value = b'packed_exts'
        inst.eg_rev_token = b'eg_rev_token'
        inst.sig = b'sig'
        expected = b"".join([
            bytes.fromhex("0000 0003 000b 0003"), b'packed_pcbm', b'packed_pm0',
            b'packed_pm1', b'packed_exts', b'eg_rev_token', b'sig'
        ])
        len_.return_value = len(expected)
        # Call
        ntools.eq_(inst.pack(), expected)


class TestADMarkingPackExt(object):
    """
    Unit test for lib.packet.pcb.ADMarking._pack_ext
    """
    def test_basic(self):
        inst = ADMarking()
        ext0 = create_mock(["EXT_TYPE", "__len__", "pack"])
        ext0.EXT_TYPE = 1
        ext0.__len__.return_value = 2
        ext0.pack.return_value = b"\x03\x04"
        ext1 = create_mock(["EXT_TYPE", "__len__", "pack"])
        ext1.EXT_TYPE = 5
        ext1.__len__.return_value = 6
        ext1.pack.return_value = b"\x07\x08"
        inst.ext = [ext0, ext1]
        # Call
        ntools.eq_(inst._pack_ext(), b"\x01\x02\x03\x04\x05\x06\x07\x08")

    def test_empty(self):
        inst = ADMarking()
        # Call
        ntools.eq_(inst._pack_ext(), b"")


class TestADMarkingRemoveSignature(object):
    """
    Unit test for lib.packet.pcb.ADMarking.remove_signature
    """
    def test(self):
        inst = ADMarking()
        inst.sig = b'sig'
        # Call
        inst.remove_signature()
        # Tests
        ntools.eq_(inst.sig, b'')


class TestADMarkingEq(object):
    """
    Unit test for lib.packet.pcb.ADMarking.__eq__
    """
    def test_equal(self):
        ad_marking1 = ADMarking.from_values('pcbm', ['pms'], b'eg_rev_token',
                                            b'sig')
        ad_marking2 = ADMarking.from_values('pcbm', ['pms'], b'eg_rev_token',
                                            b'sig')
        ntools.eq_(ad_marking1, ad_marking2)

    def test_unequal(self):
        ad_marking1 = ADMarking.from_values('pcbm', ['pms'], b'eg_rev_token',
                                            b'sig1')
        ad_marking2 = ADMarking.from_values('pcbm', ['pms'], b'eg_rev_token',
                                            b'sig2')
        ntools.assert_not_equals(ad_marking1, ad_marking2)

    def test_unequal_type(self):
        ad_marking1 = ADMarking()
        ad_marking2 = 123
        ntools.assert_not_equals(ad_marking1, ad_marking2)


class TestPathSegmentInit(object):
    """
    Unit test for lib.packet.pcb.PathSegment.__init__
    """
    @patch("lib.packet.pcb.PathSegment._parse", autospec=True)
    @patch("lib.packet.pcb.SCIONPayloadBase.__init__", autospec=True)
    def test_basic(self, super_init, parse):
        inst = PathSegment()
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.assert_is_none(inst.iof)
        ntools.eq_(inst.trc_ver, 0)
        ntools.eq_(inst.if_id, 0)
        ntools.eq_(inst.ads, [])
        ntools.eq_(inst.min_exp_time, 2 ** 8 - 1)
        ntools.assert_false(parse.called)

    @patch("lib.packet.pcb.PathSegment._parse", autospec=True)
    @patch("lib.packet.pcb.MarkingBase.__init__", autospec=True)
    def test_raw(self, super_init, parse):
        inst = PathSegment('data')
        # Tests
        parse.assert_called_once_with(inst, 'data')


class TestPathSegmentParse(object):
    """
    Unit test for lib.packet.pcb.PathSegment._parse
    """
    @patch("lib.packet.pcb.InfoOpaqueField", autospec=True)
    @patch("lib.packet.pcb.Raw", autospec=True)
    def test(self, raw, iof):
        inst = PathSegment()
        inst._parse_hops = create_mock()
        data = create_mock(["pop", "offset"])
        data.pop.side_effect = "pop iof", bytes(range(6)), "pop seg id"
        raw.return_value = data
        # Call
        ntools.eq_(inst._parse("data"), data.offset.return_value)
        # Tests
        raw.assert_called_once_with(
            "data", "PathSegment", inst.MIN_LEN, min_=True)
        iof.assert_called_once_with("pop iof")
        ntools.eq_(inst.iof, iof.return_value)
        ntools.eq_(inst.trc_ver, 0x00010203)
        ntools.eq_(inst.if_id, 0x0405)
        inst._parse_hops.assert_called_once_with(data)


class TestPathSegmentParseHops(object):
    """
    Unit test for lib.packet.pcb.PathSegment._parse_hops
    """
    @patch("lib.packet.pcb.ADMarking", autospec=True)
    def test(self, ad_marking):
        inst = PathSegment()
        inst.add_ad = create_mock()
        inst.iof = create_mock(['hops'])
        inst.iof.hops = 2
        data = create_mock(["get", "pop"])
        data.get.side_effect = bytes(range(8)), bytes(range(8, 16))
        data.pop.side_effect = "pop adm0", "pop adm1"
        ad_marking.side_effect = 'ad_marking0', 'ad_marking1'
        ad_marking.METADATA_LEN = 4
        # Call
        inst._parse_hops(data)
        # Tests
        assert_these_calls(ad_marking, (call("pop adm0"), call("pop adm1")))
        assert_these_calls(inst.add_ad,
                           (call('ad_marking0'), call('ad_marking1')))


class TestPathSegmentPack(object):
    """
    Unit test for lib.packet.pcb.PathSegment.pack
    """
    def test(self):
        inst = PathSegment()
        inst.iof = create_mock(['pack'])
        inst.iof.pack.return_value = b'packed_iof'
        (inst.trc_ver, inst.if_id) = (1, 2)
        for i in range(2):
            marking = create_mock(["pack"])
            marking.pack.return_value = bytes("ad_marking%d" % i, "ascii")
            inst.ads.append(marking)
        expected = b"".join([
            b'packed_iof', bytes.fromhex("00 00 00 01 00 02"),
            b'ad_marking0', b'ad_marking1',
        ])
        # Call
        ntools.eq_(inst.pack(), expected)


class TestPathSegmentAddAd(object):
    """
    Unit test for lib.packet.pcb.PathSegment.add_ad
    """
    def test_lower(self):
        inst = PathSegment()
        inst.iof = create_mock(['hops'])
        inst.ads = ["ad0"]
        ad_marking = create_mock(['pcbm'])
        ad_marking.pcbm = create_mock(['hof'])
        ad_marking.pcbm.hof = create_mock(['exp_time'])
        ad_marking.pcbm.hof.exp_time = inst.min_exp_time - 1
        # Call
        inst.add_ad(ad_marking)
        # Tests
        ntools.eq_(inst.min_exp_time, ad_marking.pcbm.hof.exp_time)
        ntools.eq_(inst.ads, ["ad0", ad_marking])
        ntools.eq_(inst.iof.hops, 2)

    def test_higher_exp_time(self):
        inst = PathSegment()
        inst.iof = create_mock(['hops'])
        initial_exp_time = inst.min_exp_time
        ad_marking = create_mock(['pcbm'])
        ad_marking.pcbm = create_mock(['hof'])
        ad_marking.pcbm.hof = create_mock(['exp_time'])
        ad_marking.pcbm.hof.exp_time = inst.min_exp_time + 1
        # Call
        inst.add_ad(ad_marking)
        # Tests
        ntools.eq_(inst.min_exp_time, initial_exp_time)


class TestPathSegmentRemoveSignatures(object):
    """
    Unit test for lib.packet.pcb.PathSegment.remove_signatures
    """
    def test(self):
        inst = PathSegment()
        for _ in range(3):
            inst.ads.append(create_mock(['remove_signature']))
        # Call
        inst.remove_signatures()
        # Tests
        for ad in inst.ads:
            ad.remove_signature.assert_called_once_with()


class TestPathSegmentGetPath(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_path
    """
    @patch("lib.packet.pcb.CorePath.from_values", spec_set=CorePath.from_values)
    def test_basic(self, core_path):
        path_segment = PathSegment()
        path_segment.iof = 1
        ads = [create_mock(['pcbm']) for i in range(3)]
        for i, ad in enumerate(ads):
            ad.pcbm = create_mock(['hof'])
            ad.pcbm.hof = i
        path_segment.ads = ads
        core_path.return_value = 'core_path'
        ntools.eq_(path_segment.get_path(), 'core_path')
        core_path.assert_called_once_with(1, [0, 1, 2])

    @patch("lib.packet.pcb.CorePath.from_values", spec_set=CorePath.from_values)
    def _check_reverse(self, flag, core_path):
        path_segment = PathSegment()
        path_segment.iof = create_mock(['up_flag'])
        type(path_segment.iof).__copy__ = lambda self: self
        path_segment.iof.up_flag = flag
        core_path.return_value = 'core_path'
        ntools.eq_(path_segment.get_path(reverse_direction=True), 'core_path')
        ntools.eq_(path_segment.iof.up_flag, not flag)
        core_path.assert_called_once_with(path_segment.iof, [])

    def test_reverse(self):
        for flag in True, False:
            yield self._check_reverse, flag


class TestPathSegmentGetIsd(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_isd
    """
    def test(self):
        path_segment = PathSegment()
        path_segment.iof = create_mock(['isd_id'])
        ntools.eq_(path_segment.iof.isd_id, path_segment.get_isd())


class TestPathSegmentGetLastAdm(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_last_adm
    """
    def test_basic(self):
        path_segment = PathSegment()
        path_segment.ads = [create_mock() for i in range(3)]
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
        path_segment.ads = [create_mock(['pcbm']) for i in range(3)]
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
        path_segment.ads = [create_mock(['pcbm']) for i in range(3)]
        ntools.eq_(path_segment.get_first_pcbm(), path_segment.ads[0].pcbm)

    def test_empty(self):
        path_segment = PathSegment()
        ntools.assert_is_none(path_segment.get_first_pcbm())


class TestPathSegmentCompareHops(object):
    """
    Unit test for lib.packet.pcb.PathSegment.compare_hops
    """
    def _setup(self, self_ad_nums, other_ad_nums):
        inst = PathSegment()
        for i in self_ad_nums:
            ad = create_mock(['pcbm'])
            ad.pcbm = create_mock(['ad_id'])
            ad.pcbm.ad_id = i
            inst.ads.append(ad)
        other = MagicMock(spec=PathSegment)
        other.ads = []
        for i in other_ad_nums:
            ad = create_mock(['pcbm'])
            ad.pcbm = create_mock(['ad_id'])
            ad.pcbm.ad_id = i
            other.ads.append(ad)
        return inst, other

    def test_equal(self):
        inst, other = self._setup((0, 1, 2), (0, 1, 2))
        ntools.assert_true(inst.compare_hops(other))

    def test_unequal(self):
        inst, other = self._setup((0, 1, 2), (1, 2))
        ntools.assert_false(inst.compare_hops(other))

    def test_wrong_type(self):
        inst, _ = self._setup((0, 1, 2), ())
        ntools.assert_false(inst.compare_hops(123))


class TestPathSegmentGetHopsHash(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_hops_hash
    """
    def setUp(self):
        self.ads = [create_mock(['pcbm', 'eg_rev_token', 'pms']) for i in
                    range(2)]
        for i, ad in enumerate(self.ads):
            ad.pcbm = create_mock(['ig_rev_token'])
            ad.pcbm.ig_rev_token = 'pcbm_ig_rev' + str(i)
            ad.eg_rev_token = 'eg_rev' + str(i)
            ad.pms = [create_mock(['ig_rev_token']) for j in range(2)]
            for j, pm in enumerate(ad.pms):
                pm.ig_rev_token = 'pm_ig_rev' + str(i) + str(j)
        self.calls = [call('pcbm_ig_rev0'), call('eg_rev0'),
                      call('pm_ig_rev00'), call('pm_ig_rev01'),
                      call('pcbm_ig_rev1'), call('eg_rev1'),
                      call('pm_ig_rev10'), call('pm_ig_rev11')]
        self.h = create_mock(['update', 'digest', 'hexdigest'])
        self.h.digest.return_value = 'digest'
        self.h.hexdigest.return_value = 'hexdigest'
        self.path_segment = PathSegment()
        self.path_segment.ads = self.ads

    def tearDown(self):
        del self.ads
        del self.calls
        del self.h
        del self.path_segment

    @patch("lib.packet.pcb.SHA256", autospec=True)
    def test_basic(self, sha):
        sha.new.return_value = self.h
        ntools.eq_(self.path_segment.get_hops_hash(), 'digest')
        sha.new.assert_called_once_with()
        self.h.update.assert_has_calls(self.calls)
        self.h.digest.assert_called_once_with()

    @patch("lib.packet.pcb.SHA256", autospec=True)
    def test_hex(self, sha):
        sha.new.return_value = self.h
        ntools.eq_(self.path_segment.get_hops_hash(hex=True), 'hexdigest')
        self.h.hexdigest.assert_called_once_with()


class TestPathSegmentGetNPeerLinks(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_n_peer_links
    """
    def test(self):
        inst = PathSegment()
        for i in 10, 20, 30:
            ad = create_mock(['pms'])
            ad.pms = create_mock(['__len__'])
            ad.pms.__len__.return_value = i
            inst.ads.append(ad)
        # Call
        ntools.eq_(inst.get_n_peer_links(), 60)


class TestPathSegmentGetNHops(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_n_hops
    """
    def test(self):
        ads = create_mock(['__len__'])
        ads.__len__.return_value = 123
        path_segment = PathSegment()
        path_segment.ads = ads
        ntools.eq_(path_segment.get_n_hops(), 123)


class TestPathSegmentGetTimestamp(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_timestamp
    """
    def test(self):
        iof = create_mock(['timestamp'])
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
        path_segment.iof = create_mock(['timestamp'])
        path_segment.iof.timestamp = 456
        path_segment.set_timestamp(123)
        ntools.eq_(path_segment.iof.timestamp, 123)


class TestPathSegmentGetExpirationTime(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_expiration_time
    """
    def test(self):
        path_segment = PathSegment()
        path_segment.iof = create_mock(['timestamp'])
        path_segment.iof.timestamp = 123
        path_segment.min_exp_time = 456
        ntools.eq_(path_segment.get_expiration_time(),
                   123 + int(456 * EXP_TIME_UNIT))


class TestPathSegmentGetAllIftokens(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_all_iftokens
    """
    def test(self):
        inst = PathSegment()
        for i in range(2):
            ad = create_mock(['pcbm', 'eg_rev_token', 'pms'])
            ad.pcbm = create_mock(['ig_rev_token'])
            ad.pcbm.ig_rev_token = "ig_rev_token%d" % i
            ad.eg_rev_token = "eg_rev_token%d" % i
            ad.pms = []
            for j in range(2):
                pm = create_mock(['ig_rev_token'])
                pm.ig_rev_token = "pm_ig_rev_token%d.%d" % (i, j)
                ad.pms.append(pm)
            inst.ads.append(ad)
        expected = [
            'ig_rev_token0', 'eg_rev_token0',
            'pm_ig_rev_token0.0', 'pm_ig_rev_token0.1',
            'ig_rev_token1', 'eg_rev_token1',
            'pm_ig_rev_token1.0', 'pm_ig_rev_token1.1',
        ]
        # Call
        ntools.eq_(inst.get_all_iftokens(), expected)


class TestPathSegmentDeserialize(object):
    """
    Unit test for lib.packet.pcb.PathSegment.deserialize
    """
    @patch("lib.packet.pcb.PathSegment", autospec=True)
    @patch("lib.packet.pcb.Raw", autospec=True)
    def test(self, raw, path_seg):
        data = create_mock(["__len__", "get", "pop"])
        data.__len__.side_effect = [2, 1, 0]
        data.get.side_effect = ["data0", "data1"]
        raw.return_value = data
        pcbs = []
        for i in range(2):
            pcb = create_mock(["__len__"])
            pcb.__len__.return_value = i
            pcbs.append(pcb)
        path_seg.side_effect = pcbs
        # Call
        ntools.eq_(PathSegment.deserialize("data"), pcbs)
        # Tests
        raw.assert_called_once_with("data", "PathSegment")
        assert_these_calls(path_seg, [call("data0"), call("data1")])
        assert_these_calls(data.pop, [call(0), call(1)])


class TestPathSegmentSerialize(object):
    """
    Unit test for lib.packet.pcb.PathSegment.serialize
    """
    def test(self):
        pcbs = []
        for i in range(3):
            pcb = create_mock(['pack'])
            pcb.pack.return_value = bytes("data%d" % i, "ascii")
            pcbs.append(pcb)
        ntools.eq_(PathSegment.serialize(pcbs),
                   b''.join([b'data0', b'data1', b'data2']))


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


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
