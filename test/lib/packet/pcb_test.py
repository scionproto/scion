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
from unittest.mock import patch, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.packet.path import CorePath
from lib.packet.pcb import (
    ASMarking,
    PCBMarking,
    PCBType,
    PathSegment,
    REV_TOKEN_LEN,
    parse_pcb_payload,
)
from lib.defines import EXP_TIME_UNIT
from test.testcommon import assert_these_calls, create_mock


class TestPCBMarkingParse(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.parse
    """
    @patch("lib.packet.pcb.HopOpaqueField", autospec=True)
    @patch("lib.packet.pcb.ISD_AS", autospec=True)
    @patch("lib.packet.pcb.Raw", autospec=True)
    def test(self, raw, isd_as, hof):
        inst = PCBMarking()
        data = create_mock(["pop"])
        data.pop.side_effect = "pop isd_as", "pop hof", "pop rev tkn"
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.LEN)
        isd_as.assert_called_once_with("pop isd_as")
        ntools.eq_(inst.isd_as, isd_as.return_value)
        hof.assert_called_once_with("pop hof")
        ntools.eq_(inst.hof, hof.return_value)
        ntools.eq_(inst.ig_rev_token, "pop rev tkn")


class TestPCBMarkingPack(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.pack
    """
    @patch("lib.packet.pcb.PCBMarking.__len__", autospec=True)
    def test(self, len_):
        inst = PCBMarking()
        inst.isd_as = create_mock(["pack"])
        inst.isd_as.pack.return_value = b"isd-as"
        inst.ig_rev_token = b'ig_rev_token'
        inst.hof = create_mock(['pack'])
        inst.hof.pack.return_value = b'hof'
        expected = b'isd-as' b'hof' b'ig_rev_token'
        len_.return_value = len(expected)
        # Call
        ntools.eq_(inst.pack(), expected)


class TestASMarkingParse(object):
    """
    Unit test for lib.packet.pcb.ASMarking._parse
    """
    @patch("lib.packet.pcb.PCBMarking", autospec=True)
    @patch("lib.packet.pcb.Raw", autospec=True)
    def test(self, raw, pcb_marking):
        inst = ASMarking()
        inst._parse_peers = create_mock()
        inst._parse_ext = create_mock()
        data = create_mock(["pop"])
        data.pop.side_effect = (
            bytes(range(ASMarking.METADATA_LEN)),
            "pop pcbm", "pop rev tkn", "pop sig")
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.MIN_LEN, min_=True)
        ntools.eq_(inst.cert_ver, 0x0001)
        ntools.eq_(inst.block_len, 0x0607)
        pcb_marking.assert_called_once_with("pop pcbm")
        ntools.eq_(inst.pcbm, pcb_marking.return_value)
        inst._parse_peers.assert_called_once_with(data, 0x0203, 0x0405)
        inst._parse_ext.assert_called_once_with(data, 0x0203)
        ntools.eq_(inst.eg_rev_token, "pop rev tkn")
        ntools.eq_(inst.sig, "pop sig")


class TestASMarkingParsePeers(object):
    """
    Unit test for lib.packet.pcb.ASMarking._parse_peers
    """
    @patch("lib.packet.pcb.PCBMarking", autospec=True)
    def test(self, pcb_marking):
        inst = ASMarking()
        data = create_mock(["__len__", "pop"])
        data.__len__.side_effect = [REV_TOKEN_LEN+2, REV_TOKEN_LEN+1, 0]
        data.pop.side_effect = ("pop pcbm0", "pop pcbm1")
        pcb_marking.side_effect = ['data0', 'data1']
        # Call
        inst._parse_peers(data, 0, 0)
        # Tests
        pcb_marking.assert_has_calls([call('pop pcbm0'), call('pop pcbm1')])
        ntools.eq_(inst.pms, ['data0', 'data1'])


class TestASMarkingParseExt(object):
    """
    Unit test for lib.packet.pcb.ASMarking._parse_ext
    """
    @patch("lib.packet.pcb.PCB_EXTENSION_MAP", new_callable=dict)
    def test(self, ext_map):
        inst = ASMarking()
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


class TestASMarkingFromValues(object):
    """
    Unit test for lib.packet.pcb.ASMarking.from_values
    """
    def test_full(self):
        pcbm = create_mock()
        pms = ['pms0', 'pms1']
        eg_rev_token = bytes(range(REV_TOKEN_LEN))
        sig = b'sig_bytes'
        ext = ['ext1', 'ext22']
        # Call
        inst = ASMarking.from_values(pcbm, pms, eg_rev_token, sig, ext)
        # Tests
        ntools.assert_is_instance(inst, ASMarking)
        ntools.eq_(inst.pcbm, pcbm)
        ntools.eq_(inst.pms, pms)
        ntools.eq_(inst.block_len, 3 * PCBMarking.LEN)
        ntools.eq_(inst.sig, sig)
        ntools.eq_(inst.ext, ext)
        ntools.eq_(inst.eg_rev_token, eg_rev_token)

    def test_min(self):
        inst = ASMarking.from_values()
        ntools.assert_is_none(inst.pcbm)
        ntools.eq_(inst.pms, [])
        ntools.eq_(inst.block_len, PCBMarking.LEN)
        ntools.eq_(inst.sig, b'')
        ntools.eq_(inst.ext, [])
        ntools.eq_(inst.eg_rev_token, bytes(REV_TOKEN_LEN))


class TestASMarkingPack(object):
    """
    Unit test for lib.packet.pcb.ASMarking.pack
    """
    @patch("lib.packet.pcb.ASMarking.__len__", autospec=True)
    def test(self, len_):
        inst = ASMarking()
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


class TestASMarkingPackExt(object):
    """
    Unit test for lib.packet.pcb.ASMarking._pack_ext
    """
    def test_basic(self):
        inst = ASMarking()
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
        inst = ASMarking()
        # Call
        ntools.eq_(inst._pack_ext(), b"")


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
    @patch("lib.packet.pcb.ASMarking", autospec=True)
    def test(self, asm):
        inst = PathSegment()
        inst.add_as = create_mock()
        inst.iof = create_mock(['hops'])
        inst.iof.hops = 2
        data = create_mock(["get", "pop"])
        data.get.side_effect = bytes(range(8)), bytes(range(8, 16))
        data.pop.side_effect = "pop asm0", "pop asm1"
        asm.side_effect = 'asm0', 'asm1'
        asm.METADATA_LEN = 4
        # Call
        inst._parse_hops(data)
        # Tests
        assert_these_calls(asm, (call("pop asm0"), call("pop asm1")))
        assert_these_calls(inst.add_as, (call('asm0'), call('asm1')))


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
            marking.pack.return_value = bytes("asm%d" % i, "ascii")
            inst.ases.append(marking)
        expected = b"".join([
            b'packed_iof', bytes.fromhex("00 00 00 01 00 02"), b'asm0', b'asm1',
        ])
        # Call
        ntools.eq_(inst.pack(), expected)


class TestPathSegmentAddAs(object):
    """
    Unit test for lib.packet.pcb.PathSegment.add_as
    """
    def test_lower(self):
        inst = PathSegment()
        inst.iof = create_mock(['hops'])
        inst.ases = ["as0"]
        asm = create_mock(['pcbm'])
        asm.pcbm = create_mock(['hof'])
        asm.pcbm.hof = create_mock(['exp_time'])
        asm.pcbm.hof.exp_time = inst.min_exp_time - 1
        # Call
        inst.add_as(asm)
        # Tests
        ntools.eq_(inst.min_exp_time, asm.pcbm.hof.exp_time)
        ntools.eq_(inst.ases, ["as0", asm])
        ntools.eq_(inst.iof.hops, 2)

    def test_higher_exp_time(self):
        inst = PathSegment()
        inst.iof = create_mock(['hops'])
        initial_exp_time = inst.min_exp_time
        asm = create_mock(['pcbm'])
        asm.pcbm = create_mock(['hof'])
        asm.pcbm.hof = create_mock(['exp_time'])
        asm.pcbm.hof.exp_time = inst.min_exp_time + 1
        # Call
        inst.add_as(asm)
        # Tests
        ntools.eq_(inst.min_exp_time, initial_exp_time)


class TestPathSegmentGetPath(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_path
    """
    @patch("lib.packet.pcb.CorePath.from_values", spec_set=CorePath.from_values)
    def test_basic(self, core_path):
        inst = PathSegment()
        inst.iof = 1
        ases = [create_mock(['pcbm']) for i in range(3)]
        for i, asm in enumerate(ases):
            asm.pcbm = create_mock(['hof'])
            asm.pcbm.hof = i
        inst.ases = ases
        core_path.return_value = 'core_path'
        ntools.eq_(inst.get_path(), 'core_path')
        core_path.assert_called_once_with(1, [0, 1, 2])

    @patch("lib.packet.pcb.CorePath.from_values", spec_set=CorePath.from_values)
    def _check_reverse(self, flag, core_path):
        inst = PathSegment()
        inst.iof = create_mock(['up_flag'])
        type(inst.iof).__copy__ = lambda self: self
        inst.iof.up_flag = flag
        core_path.return_value = 'core_path'
        ntools.eq_(inst.get_path(reverse_direction=True), 'core_path')
        ntools.eq_(inst.iof.up_flag, not flag)
        core_path.assert_called_once_with(inst.iof, [])

    def test_reverse(self):
        for flag in True, False:
            yield self._check_reverse, flag


class TestPathSegmentGetHopsHash(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_hops_hash
    """
    def _setup(self):
        ases = []
        for i in range(2):
            ases.append(create_asm(i))
        h = create_mock(['update', 'digest', 'hexdigest'])
        h.digest.return_value = 'digest'
        h.hexdigest.return_value = 'hexdigest'
        inst = PathSegment()
        inst.ases = ases
        return inst, h

    @patch("lib.packet.pcb.SHA256", autospec=True)
    def test_basic(self, sha):
        inst, h = self._setup()
        sha.new.return_value = h
        # Call
        ntools.eq_(inst.get_hops_hash(), 'digest')
        # Tests
        assert_these_calls(h.update, [
            call("pcbm_ig_rev 0"), call("eg_rev 0"),
            call("pm_ig_rev 0,0"), call("pm_ig_rev 0,1"),
            call("pcbm_ig_rev 1"), call("eg_rev 1"),
            call("pm_ig_rev 1,0"), call("pm_ig_rev 1,1"),
        ])

    @patch("lib.packet.pcb.SHA256", autospec=True)
    def test_hex(self, sha):
        inst, h = self._setup()
        sha.new.return_value = h
        # Call
        ntools.eq_(inst.get_hops_hash(hex=True), 'hexdigest')


class TestPathSegmentGetExpirationTime(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_expiration_time
    """
    def test(self):
        inst = PathSegment()
        inst.iof = create_mock(['timestamp'])
        inst.iof.timestamp = 123
        inst.min_exp_time = 456
        ntools.eq_(inst.get_expiration_time(), 123 + int(456 * EXP_TIME_UNIT))


class TestPathSegmentGetAllIftokens(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_all_iftokens
    """
    def test(self):
        inst = PathSegment()
        for i in range(2):
            inst.ases.append(create_asm(i))
        expected = [
            'pcbm_ig_rev 0', 'eg_rev 0', 'pm_ig_rev 0,0', 'pm_ig_rev 0,1',
            'pcbm_ig_rev 1', 'eg_rev 1', 'pm_ig_rev 1,0', 'pm_ig_rev 1,1',
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
    Unit tests for lib.packet.pcb.PathSegment.serialize
    """
    def test(self):
        pcbs = []
        for i in range(3):
            pcb = create_mock(['pack'])
            pcb.pack.return_value = bytes("data%d" % i, "ascii")
            pcbs.append(pcb)
        ntools.eq_(PathSegment.serialize(pcbs),
                   b''.join([b'data0', b'data1', b'data2']))


class TestParsePcbPayload(object):
    """
    Unit tests for lib.packet.pcb.parse_pcb_payload
    """
    @patch("lib.packet.pcb.PathSegment", autospec=True)
    def test_success(self, path_seg):
        data = create_mock(["pop"])
        # Call
        inst = parse_pcb_payload(PCBType.SEGMENT, data)
        # Tests
        ntools.eq_(inst, path_seg.return_value)

    def test_unknown(self):
        ntools.assert_raises(SCIONParseError, parse_pcb_payload, 99, "data")


def create_asm(i):
    asm = create_mock(['pcbm', 'eg_rev_token', 'pms'])
    asm.pcbm = create_mock(['ig_rev_token'])
    asm.pcbm.ig_rev_token = 'pcbm_ig_rev %s' % i
    asm.eg_rev_token = 'eg_rev %s' % i
    asm.pms = []
    for j in range(2):
        asm.pms.append(create_pm(i, j))
    return asm


def create_pm(i, j):
    pm = create_mock(['ig_rev_token'])
    pm.ig_rev_token = 'pm_ig_rev %s,%s' % (i, j)
    return pm


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
