# Copyright 2014 ETH Zurich
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
:mod:`lib_packet_scion_test` --- lib.packet.scion unit tests
============================================================
"""
# Stdlib
from unittest.mock import patch, MagicMock, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.defines import L4_NONE
from lib.packet.ext_hdr import ExtensionHeader
from lib.packet.path import PathBase
from lib.packet.packet_base import L4HeaderBase
from lib.packet.scion import (
    IFIDPayload,
    IFIDType,
    SCIONAddrHdr,
    SCIONBasePacket,
    SCIONCommonHdr,
    SCIONExtPacket,
    SCIONL4Packet,
    build_base_hdrs,
    parse_ifid_payload,
)
from lib.packet.scion_addr import ISD_AD
from lib.types import PayloadClass
from test.testcommon import (
    assert_these_call_lists,
    assert_these_calls,
    create_mock,
)


class TestSCIONCommonHdrInit(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.__init__
    """
    @patch("lib.packet.scion.SCIONCommonHdr._parse", autospec=True)
    @patch("lib.packet.scion.HeaderBase.__init__", autospec=True,
           return_value=None)
    def test_basic(self, super_init, parse):
        inst = SCIONCommonHdr()
        super_init.assert_called_once_with(inst)
        ntools.eq_(inst.version, 0)
        ntools.assert_is_none(inst.src_addr_type)
        ntools.assert_is_none(inst.dst_addr_type)
        ntools.assert_is_none(inst.total_len)
        ntools.assert_is_none(inst._iof_idx)
        ntools.assert_is_none(inst._hof_idx)
        ntools.assert_is_none(inst.next_hdr)
        ntools.assert_is_none(inst.hdr_len)
        ntools.assert_false(parse.called)

    @patch("lib.packet.scion.SCIONCommonHdr._parse", autospec=True)
    @patch("lib.packet.scion.HeaderBase.__init__", autospec=True,
           return_value=None)
    def test_raw(self, super_init, parse):
        hdr = SCIONCommonHdr('data')
        parse.assert_called_once_with(hdr, 'data')


class TestSCIONCommonHdrParse(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr._parse
    """
    @patch("lib.packet.scion.SCIONAddrHdr.calc_len", new_callable=create_mock)
    @patch("lib.packet.scion.Raw", autospec=True)
    def test(self, raw, calc_len):
        # Setup
        inst = SCIONCommonHdr()
        data = create_mock(["pop"])
        data.pop.return_value = bytes([0b11110000, 0b00111111]) + \
            bytes.fromhex('0304 38 40 07 08')
        raw.return_value = data
        calc_len.return_value = 24
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "SCIONCommonHdr", inst.LEN)
        ntools.eq_(inst.total_len, 0x0304)
        ntools.eq_(inst.next_hdr, 0x07)
        ntools.eq_(inst.hdr_len, 0x08)
        ntools.eq_(inst.version, 0b1111)
        ntools.eq_(inst.src_addr_type, 0b000000)
        ntools.eq_(inst.dst_addr_type, 0b111111)
        calc_len.assert_called_once_with(0b000000, 0b111111)
        ntools.eq_(inst.addrs_len, 24)
        ntools.eq_(inst._iof_idx, 3)
        ntools.eq_(inst._hof_idx, 4)


class TestSCIONCommonHdrFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.from_values
    """
    @patch("lib.packet.scion.SCIONAddrHdr.calc_len", new_callable=create_mock)
    def test_full(self, calc_len):
        # Setup
        src_type = 1
        dst_type = 2
        calc_len.return_value = 44
        hdr_len = SCIONCommonHdr.LEN + 44
        # Call
        inst = SCIONCommonHdr.from_values(src_type, dst_type, 3)
        # Tests
        ntools.assert_is_instance(inst, SCIONCommonHdr)
        ntools.eq_(inst.src_addr_type, src_type)
        ntools.eq_(inst.dst_addr_type, dst_type)
        calc_len.assert_called_once_with(src_type, dst_type)
        ntools.eq_(inst.addrs_len, 44)
        ntools.eq_(inst.next_hdr, 3)
        ntools.eq_(inst.hdr_len, hdr_len)
        ntools.eq_(inst.total_len, hdr_len)

    @patch("lib.packet.scion.SCIONAddrHdr.calc_len", new_callable=create_mock)
    def test_min(self, calc_len):
        # Setup
        calc_len.return_value = 44
        # Call
        inst = SCIONCommonHdr.from_values(0, 1)
        # Tests
        ntools.eq_(inst.next_hdr, L4_NONE)


class TestSCIONCommonHdrPack(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.pack
    """
    def test(self):
        inst = SCIONCommonHdr()
        inst.version = 0b1111
        inst.src_addr_type = 0b000000
        inst.dst_addr_type = 0b111111
        inst.addrs_len = 24
        inst.total_len = 0x304
        inst._iof_idx = 3
        inst._hof_idx = 4
        inst.next_hdr = 0x7
        inst.hdr_len = 0x8
        expected = b"".join([
            bytes([0b11110000, 0b00111111]),
            bytes.fromhex('0304 38 40 07 08'),
        ])
        # Call
        ntools.eq_(inst.pack(), expected)


class TestSCIONCommonHdrGetOfIdxs(object):
    """
    Unit tests for inst.packet.scion.SCIONCommonHdr.get_of_idxs
    """
    def test(self):
        inst = SCIONCommonHdr()
        inst._iof_idx = 42
        inst._hof_idx = 73
        # Call
        ntools.eq_(inst.get_of_idxs(), (42, 73))


class TestSCIONCommonHdrSetOfIdxs(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.set_of_idxs
    """
    def test(self):
        inst = SCIONCommonHdr()
        inst._iof_idx = 42
        inst._hof_idx = 73
        # Call
        inst.set_of_idxs(11, 23)
        # Tests
        ntools.eq_(inst._iof_idx, 11)
        ntools.eq_(inst._hof_idx, 23)


class TestSCIONCommonHdrStr(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.__str__
    """
    @patch("lib.packet.scion.haddr_get_type", autospec=True)
    def test(self, get_type):
        inst = SCIONCommonHdr()
        inst.version = 0b1111
        inst.src_addr_type = 0b000000
        inst.dst_addr_type = 0b111111
        inst.addrs_len = 24
        inst.total_len = 0x304
        inst._iof_idx = 3
        inst._hof_idx = 4
        inst.next_hdr = 0x7
        inst.hdr_len = 0x8
        addr_type = create_mock(['NAME'])
        addr_type.NAME = "name"
        get_type.return_value = addr_type
        # Call
        str(inst)


class TestSCIONAddrHdrInit(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr.__init__
    """
    @patch("lib.packet.scion.SCIONAddrHdr._parse", autospec=True)
    @patch("lib.packet.scion.HeaderBase.__init__", autospec=True)
    def test_basic(self, super_init, parse):
        inst = SCIONAddrHdr()
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.assert_is_none(inst.src_isd)
        ntools.assert_is_none(inst.src_ad)
        ntools.assert_is_none(inst.src_addr)
        ntools.assert_is_none(inst.dst_isd)
        ntools.assert_is_none(inst.dst_ad)
        ntools.assert_is_none(inst.dst_addr)
        ntools.assert_is_none(inst._pad_len)
        ntools.assert_is_none(inst._total_len)
        ntools.assert_false(parse.called)

    @patch("lib.packet.scion.SCIONAddrHdr._parse", autospec=True)
    @patch("lib.packet.scion.HeaderBase.__init__", autospec=True)
    def test_parse(self, super_init, parse):
        inst = SCIONAddrHdr((1, 2, 3))
        # Tests
        parse.assert_called_once_with(inst, 1, 2, 3)


class TestSCIONAddrHdrParse(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr._parse
    """
    @patch("lib.packet.scion.SCIONAddrHdr.update", autospec=True)
    @patch("lib.packet.scion.ISD_AD.from_raw", new_callable=create_mock)
    @patch("lib.packet.scion.haddr_get_type", autospec=True)
    @patch("lib.packet.scion.SCIONAddrHdr.calc_len", new_callable=create_mock)
    @patch("lib.packet.scion.Raw", autospec=True)
    def test(self, raw, calc_len, get_type, isd_ad, update):
        inst = SCIONAddrHdr()
        data = create_mock(["pop"])
        data.pop.side_effect = [
            "src isd ad", "src addr", "dst isd ad", "dst addr",
        ]
        raw.return_value = data
        src_class = create_mock(["LEN"])
        dst_class = create_mock(["LEN"])
        # Need special handling for setting side_effects on autospec'd mocks
        # (https://bugs.python.org/issue17826)
        get_type.side_effect = iter([src_class, dst_class])
        isd_ad.side_effect = (
            ("src isd", "src ad"), ("dst isd", "dst ad"),
        )
        src_type = 1
        dst_type = 2
        # Call
        inst._parse(src_type, dst_type, "data")
        # Tests
        raw.assert_called_once_with("data", "SCIONAddrHdr",
                                    calc_len.return_value)
        ntools.eq_(inst.src_isd, "src isd")
        ntools.eq_(inst.src_ad, "src ad")
        src_class.assert_called_once_with("src addr")
        ntools.eq_(inst.src_addr, src_class.return_value)
        ntools.eq_(inst.dst_isd, "dst isd")
        ntools.eq_(inst.dst_ad, "dst ad")
        dst_class.assert_called_once_with("dst addr")
        ntools.eq_(inst.dst_addr, dst_class.return_value)
        update.assert_called_once_with(inst)


class TestSCIONAddrHdrFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr.from_values
    """
    @patch("lib.packet.scion.SCIONAddrHdr.update", autospec=True)
    def test(self, update):
        src = create_mock(["isd_id", "ad_id", "host_addr"])
        src.host_addr = create_mock(["TYPE"])
        src.host_addr.TYPE = 1
        dst = create_mock(["isd_id", "ad_id", "host_addr"])
        dst.host_addr = create_mock(["TYPE"])
        dst.host_addr.TYPE = 2
        # Call
        inst = SCIONAddrHdr.from_values(src, dst)
        # Tests
        ntools.assert_is_instance(inst, SCIONAddrHdr)
        ntools.eq_(inst.src_isd, src.isd_id)
        ntools.eq_(inst.src_ad, src.ad_id)
        ntools.eq_(inst.src_addr, src.host_addr)
        ntools.eq_(inst.dst_isd, dst.isd_id)
        ntools.eq_(inst.dst_ad, dst.ad_id)
        ntools.eq_(inst.dst_addr, dst.host_addr)
        update.assert_called_once_with(inst)


class TestSCIONAddrHdrPack(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr.pack
    """
    @patch("lib.packet.scion.SCIONAddrHdr.__len__", autospec=True)
    @patch("lib.packet.scion.ISD_AD", autospec=True)
    @patch("lib.packet.scion.SCIONAddrHdr.update", autospec=True)
    def test(self, update, isd_ad, len_):
        inst = SCIONAddrHdr()
        src_addr = create_mock(["pack"])
        src_addr.pack.return_value = b"src host addr"
        dst_addr = create_mock(["pack"])
        dst_addr.pack.return_value = b"dst host addr"
        inst.src_isd = 1
        inst.src_ad = 11
        inst.src_addr = src_addr
        inst.dst_isd = 2
        inst.dst_ad = 22
        inst.dst_addr = dst_addr
        inst._total_len = 48
        inst._pad_len = 2
        isd_ad_obj = create_mock(["pack"])
        isd_ad_obj.pack.side_effect = [b"src isd ad", b"dst isd ad"]
        isd_ad.return_value = isd_ad_obj
        expected = b"src isd ad" b"src host addr" b"dst isd ad" b"dst host addr"
        expected += bytes(2)
        len_.return_value = len(expected)
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        update.assert_called_once_with(inst)
        assert_these_call_lists(isd_ad, [
            call(1, 11).pack(), call(2, 22).pack()])


class TestSCIONAddrHdrUpdate(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr.update
    """
    @patch("lib.packet.scion.SCIONAddrHdr.calc_len", new_callable=create_mock)
    def test(self, calc_len):
        inst = SCIONAddrHdr()
        calc_len.return_value = 1, 3
        inst.src_addr = create_mock(["TYPE"])
        inst.dst_addr = create_mock(["TYPE"])
        # Call
        inst.update()
        # Tests
        calc_len.assert_called_once_with(inst.src_addr.TYPE, inst.dst_addr.TYPE,
                                         both=True)
        ntools.eq_(inst._total_len, 1)
        ntools.eq_(inst._pad_len, 3)


class TestSCIONAddrHdrCalcLen(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr.calc_len
    """
    @patch("lib.packet.scion.calc_padding", autospec=True)
    @patch("lib.packet.scion.haddr_get_type", autospec=True)
    def _check(self, type_lens, both, exp_total, exp_pad, get_type,
               calc_padding):
        src_class = create_mock(["LEN"])
        dst_class = create_mock(["LEN"])
        src_class.LEN, dst_class.LEN = type_lens
        get_type.side_effect = iter([src_class, dst_class])
        calc_padding.return_value = exp_pad
        # Call
        results = SCIONAddrHdr.calc_len(1, 2, both=both)
        # Tests
        assert_these_calls(get_type, [call(1), call(2)])
        calc_padding.assert_called_once_with(
            ISD_AD.LEN * 2 + sum(type_lens), SCIONAddrHdr.BLK_SIZE)
        if both:
            ntools.eq_(results, (exp_total, exp_pad))
        else:
            ntools.eq_(results, exp_total)

    def test(self):
        for type_lens, exp_total, exp_pad in (
            ((4, 12), 24, 0),  # no padding required
            ((4, 15), 32, 5),  # padding required
        ):
            yield self._check, type_lens, False, exp_total, exp_pad
            yield self._check, type_lens, True, exp_total, exp_pad


class TestSCIONAddrHdrReverse(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr.reverse
    """
    @patch("lib.packet.scion.SCIONAddrHdr.update", autospec=True)
    def test(self, update):
        inst = SCIONAddrHdr()
        inst.src_isd = "src isd"
        inst.src_ad = "src ad"
        inst.src_addr = "src addr"
        inst.dst_isd = "dst isd"
        inst.dst_ad = "dst ad"
        inst.dst_addr = "dst addr"
        # Call
        inst.reverse()
        # Tests
        ntools.eq_(inst.src_isd, "dst isd")
        ntools.eq_(inst.src_ad, "dst ad")
        ntools.eq_(inst.src_addr, "dst addr")
        ntools.eq_(inst.dst_isd, "src isd")
        ntools.eq_(inst.dst_ad, "src ad")
        ntools.eq_(inst.dst_addr, "src addr")
        update.assert_called_once_with(inst)


class TestSCIONAddrHdrLen(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr.__len__
    """
    def test(self):
        inst = SCIONAddrHdr()
        inst._total_len = 42
        # Call
        ntools.eq_(len(inst), 42)


class TestSCIONBasePacketInit(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket.__init__
    """
    @patch("lib.packet.scion.SCIONBasePacket._parse", autospec=True)
    @patch("lib.packet.scion.PacketBase.__init__", autospec=True,
           return_value=None)
    def test_basic(self, super_init, parse):
        inst = SCIONBasePacket()
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.assert_is_none(inst.cmn_hdr)
        ntools.assert_is_none(inst.addrs)
        ntools.assert_is_none(inst.path)
        ntools.eq_(inst._l4_proto, L4_NONE)
        ntools.eq_(inst._payload, b"")
        ntools.assert_false(parse.called)

    @patch("lib.packet.scion.SCIONBasePacket._parse", autospec=True)
    @patch("lib.packet.scion.PacketBase.__init__", autospec=True,
           return_value=None)
    def test_parse(self, super_init, parse):
        inst = SCIONBasePacket(b"raw")
        # Tests
        parse.assert_called_once_with(inst, b"raw")


class TestSCIONBasePacketParse(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket._parse
    """
    @patch("lib.packet.scion.PayloadRaw", autospec=True)
    @patch("lib.packet.scion.Raw", autospec=True)
    def test(self, raw, pld_raw):
        inst = SCIONBasePacket()
        inst._inner_parse = create_mock()
        inst.set_payload = create_mock()
        data = create_mock(["get"])
        raw.return_value = data
        # Call
        inst._parse(b"data")
        # Tests
        raw.assert_called_once_with(b"data", "SCIONBasePacket", inst.MIN_LEN,
                                    min_=True)
        inst._inner_parse.assert_called_once_with(data)
        pld_raw.assert_called_once_with(data.get.return_value)
        inst.set_payload.assert_called_once_with(pld_raw.return_value)


class TestSCIONBasePacketInnerParse(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket._inner_parse
    """
    def test(self):
        inst = SCIONBasePacket()
        inst._parse_cmn_hdr = create_mock()
        inst._parse_addrs = create_mock()
        inst._parse_path = create_mock()
        inst.cmn_hdr = create_mock(["hdr_len"])
        inst.cmn_hdr.hdr_len = 42
        data = create_mock(["offset"])
        data.offset.return_value = 12
        # Call
        inst._inner_parse(data)
        # Tests
        inst._parse_cmn_hdr.assert_called_once_with(data)
        inst._parse_addrs.assert_called_once_with(data)
        inst._parse_path.assert_called_once_with(data, 30)


class TestSCIONBasePacketParseCmnHdr(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket._parse_cmn_hdr
    """
    @patch("lib.packet.scion.SCIONCommonHdr", autospec=True)
    def test_success(self, cmn_hdr_class):
        inst = SCIONBasePacket()
        data = create_mock(["__len__", "pop"])
        data.__len__.return_value = 42
        cmn_hdr = create_mock(["total_len"])
        cmn_hdr.total_len = 42
        cmn_hdr_class.return_value = cmn_hdr
        # Call
        inst._parse_cmn_hdr(data)
        # Tests
        cmn_hdr_class.assert_called_once_with(data.pop.return_value)
        ntools.eq_(inst.cmn_hdr, cmn_hdr)

    @patch("lib.packet.scion.SCIONCommonHdr", autospec=True)
    def test_error(self, cmn_hdr_class):
        inst = SCIONBasePacket()
        data = create_mock(["__len__", "pop"])
        data.__len__.return_value = 42
        cmn_hdr = create_mock(["total_len"])
        cmn_hdr.total_len = 41
        cmn_hdr_class.return_value = cmn_hdr
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse_cmn_hdr, data)


class TestSCIONBasePacketParseAddrs(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket._parse_addrs
    """
    @patch("lib.packet.scion.SCIONAddrHdr", autospec=True)
    def test(self, addr_hdr):
        inst = SCIONBasePacket()
        cmn_hdr = create_mock(["addrs_len", "src_addr_type", "dst_addr_type"])
        inst.cmn_hdr = cmn_hdr
        data = create_mock(["get", "pop"])
        # Call
        inst._parse_addrs(data)
        # Tests
        addr_hdr.assert_called_once_with((
            cmn_hdr.src_addr_type, cmn_hdr.dst_addr_type,
            data.get.return_value))
        ntools.eq_(inst.addrs, addr_hdr.return_value)
        data.pop.assert_called_once_with(addr_hdr.__len__.return_value)


class TestSCIONBasePacketParsePath(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket._parse_path
    """
    @patch("lib.packet.scion.parse_path", autospec=True)
    def test(self, parse_path):
        inst = SCIONBasePacket()
        inst.cmn_hdr = create_mock(["get_of_idxs"])
        inst.cmn_hdr.get_of_idxs.return_value = "iof", "hof"
        data = create_mock(["get", "pop"])
        path = create_mock(["__len__", "set_of_idxs"])
        path.__len__.return_value = 42
        parse_path.return_value = path
        # Call
        inst._parse_path(data, 20)
        # Tests
        parse_path.assert_called_once_with(data.get.return_value)
        ntools.eq_(inst.path, path)
        data.pop.assert_called_once_with(42)
        path.set_of_idxs.assert_called_once_with("iof", "hof")


class TestSCIONBasePacketFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket.from_values
    """
    @patch("lib.packet.scion.SCIONBasePacket.update", autospec=True)
    @patch("lib.packet.scion.SCIONBasePacket.set_payload", autospec=True)
    @patch("lib.packet.scion.PayloadRaw", autospec=True)
    @patch("lib.packet.scion.SCIONBasePacket._inner_from_values", autospec=True)
    def test_basic(self, inner_values, pld_raw, set_pld, update):
        inst = SCIONBasePacket.from_values("cmn hdr", "addr hdr", "path hdr")
        # Tests
        ntools.assert_is_instance(inst, SCIONBasePacket)
        inner_values.assert_called_once_with(
            inst, "cmn hdr", "addr hdr", "path hdr")
        pld_raw.assert_called_once_with(b"")
        set_pld.assert_called_once_with(inst, pld_raw.return_value)
        update.assert_called_once_with(inst)

    @patch("lib.packet.scion.SCIONBasePacket.update", autospec=True)
    @patch("lib.packet.scion.SCIONBasePacket.set_payload", autospec=True)
    @patch("lib.packet.scion.PayloadRaw", autospec=True)
    @patch("lib.packet.scion.SCIONBasePacket._inner_from_values", autospec=True)
    def test_payload(self, inner_values, pld_raw, set_pld, update):
        SCIONBasePacket.from_values("cmn hdr", "addr hdr", "path hdr",
                                    "payload")
        # Tests
        pld_raw.assert_called_once_with("payload")


class TestSCIONBasePacketInnerFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket._inner_from_values
    """
    def test(self):
        inst = SCIONBasePacket()
        cmn_hdr = MagicMock(spec_set=SCIONCommonHdr)
        addr_hdr = MagicMock(spec_set=SCIONAddrHdr)
        path_hdr = MagicMock(spec_set=PathBase)
        # Call
        inst._inner_from_values(cmn_hdr, addr_hdr, path_hdr)


class TestSCIONBasePacketPack(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket.pack
    """
    @patch("lib.packet.scion.SCIONBasePacket.update", autospec=True)
    def test(self, update):
        inst = SCIONBasePacket()
        inst.update = create_mock()
        inst.cmn_hdr = create_mock(["pack", "total_len"])
        inst.cmn_hdr.pack.return_value = b"cmn hdr"
        inst.addrs = create_mock(["pack"])
        inst.addrs.pack.return_value = b"addrs"
        inst.path = create_mock(["pack"])
        inst.path.pack.return_value = b"path"
        inst._inner_pack = create_mock()
        inst._inner_pack.return_value = b"inner pack"
        inst._payload = create_mock(["pack"])
        inst._payload.pack.return_value = b"payload"
        expected = b"cmn hdr" b"addrs" b"path" b"inner pack" b"payload"
        inst.cmn_hdr.total_len = len(expected)
        # Call
        ntools.eq_(inst.pack(),
                   b"cmn hdr" b"addrs" b"path" b"inner pack" b"payload")
        # Tests
        inst.update.assert_called_once_with()


class TestSCIONBasePacketUpdate(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket.update
    """
    def test(self):
        inst = SCIONBasePacket()
        inst.addrs = create_mock(["update"])
        inst._update_cmn_hdr = create_mock()
        # Call
        inst.update()
        # Tests
        inst.addrs.update.assert_called_once_with()
        inst._update_cmn_hdr.assert_called_once_with()


class TestSCIONBasePacketUpdateCmnHdr(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket._update_cmn_hdr
    """
    def test(self):
        inst = SCIONBasePacket()
        cmn_hdr = create_mock([
            "__len__", "src_addr_type", "dst_addr_type", "addrs_len", "hdr_len",
            "total_len", "set_of_idxs", "next_hdr", "update",
        ])
        cmn_hdr.__len__.return_value = 2
        addrs = create_mock(["__len__", "src_addr", "dst_addr"])
        addrs.__len__.return_value = 4
        addrs.src_addr = create_mock(["TYPE"])
        addrs.dst_addr = create_mock(["TYPE"])
        path = create_mock(["__len__", "get_of_idxs"])
        path.__len__.return_value = 8
        path.get_of_idxs.return_value = 3, 7
        inst.cmn_hdr = cmn_hdr
        inst.addrs = addrs
        inst.path = path
        inst._get_offset_len = create_mock()
        inst._get_offset_len.return_value = 42
        inst._get_next_hdr = create_mock()
        # Call
        inst._update_cmn_hdr()
        # Tests
        ntools.eq_(cmn_hdr.src_addr_type, addrs.src_addr.TYPE)
        ntools.eq_(cmn_hdr.dst_addr_type, addrs.dst_addr.TYPE)
        ntools.eq_(cmn_hdr.addrs_len, 4)
        ntools.eq_(cmn_hdr.hdr_len, 2 + 4 + 8)
        ntools.eq_(cmn_hdr.total_len, 14 + 42)
        cmn_hdr.set_of_idxs.assert_called_once_with(3, 7)
        ntools.eq_(cmn_hdr.next_hdr, inst._get_next_hdr.return_value)


class TestSCIONBasePacketReverse(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket.reverse
    """
    def test(self):
        inst = SCIONBasePacket()
        inst.addrs = create_mock(['reverse'])
        inst.path = create_mock(['reverse'])
        # Call
        inst.reverse()
        # Tests
        inst.addrs.reverse.assert_called_once_with()
        inst.path.reverse.assert_called_once_with()


class TestSCIONBasePacketLen(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket.__len__
    """
    def test(self):
        inst = SCIONBasePacket()
        inst.cmn_hdr = create_mock(['__len__'])
        inst.cmn_hdr.__len__.return_value = 1
        inst.addrs = create_mock(['__len__'])
        inst.addrs.__len__.return_value = 2
        inst.path = create_mock(['__len__'])
        inst.path.__len__.return_value = 4
        inst._get_offset_len = create_mock()
        inst._get_offset_len.return_value = 8
        # Call
        ntools.eq_(len(inst), 1 + 2 + 4 + 8)


class TestSCIONExtPacketInit(object):
    """
    Unit tests for lib.packet.scion.SCIONExtPacket.__init__
    """
    @patch("lib.packet.scion.SCIONExtPacket._parse", autospec=True)
    @patch("lib.packet.scion.SCIONBasePacket.__init__", autospec=True,
           return_value=None)
    def test_basic(self, super_init, parse):
        inst = SCIONExtPacket()
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.eq_(inst.ext_hdrs, [])
        ntools.assert_false(parse.called)

    @patch("lib.packet.scion.SCIONExtPacket._parse", autospec=True)
    @patch("lib.packet.scion.SCIONBasePacket.__init__", autospec=True,
           return_value=None)
    def test_raw(self, super_init, parse):
        inst = SCIONExtPacket(b"raw")
        # Tests
        parse.assert_called_once_with(inst, b"raw")


class TestSCIONExtPacketInnerParse(object):
    """
    Unit tests for lib.packet.scion.SCIONExtPacket._inner_parse
    """
    @patch("lib.packet.scion.parse_extensions", autospec=True)
    @patch("lib.packet.scion.SCIONBasePacket._inner_parse", autospec=True)
    def test(self, super_parse, parse_extns):
        inst = SCIONExtPacket()
        inst.cmn_hdr = create_mock(["next_hdr"])
        parse_extns.return_value = "ext hdrs", "l4 proto"
        # Call
        inst._inner_parse("data")
        # Tests
        super_parse.assert_called_once_with(inst, "data")
        parse_extns.assert_called_once_with("data", inst.cmn_hdr.next_hdr)
        ntools.eq_(inst.ext_hdrs, "ext hdrs")
        ntools.eq_(inst._l4_proto, "l4 proto")


class TestSCIONExtPacketFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONExtPacket.from_values
    """
    @patch("lib.packet.scion.SCIONExtPacket.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONExtPacket._inner_from_values", autospec=True)
    def test_basic(self, inner_values, set_pld):
        inst = SCIONExtPacket.from_values("cmn hdr", "addr hdr", "path hdr",
                                          "ext hdrs")
        # Tests
        ntools.assert_is_instance(inst, SCIONExtPacket)
        inner_values.assert_called_once_with(
            inst, "cmn hdr", "addr hdr", "path hdr", "ext hdrs")
        set_pld.assert_called_once_with(inst, b"")

    @patch("lib.packet.scion.SCIONExtPacket.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONExtPacket._inner_from_values", autospec=True)
    def test_payload(self, inner_values, set_pld):
        inst = SCIONExtPacket.from_values("cmn hdr", "addr hdr", "path hdr",
                                          "ext hdrs", "payload")
        # Tests
        set_pld.assert_called_once_with(inst, "payload")


class TestSCIONExtPacketInnerFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONExtPacket._inner_from_values
    """
    @patch("lib.packet.scion.SCIONBasePacket._inner_from_values", autospec=True)
    def test(self, super_values):
        inst = SCIONExtPacket()
        ext_hdrs = []
        for _ in range(3):
            ext_hdrs.append(MagicMock(spec_set=ExtensionHeader))
        # Call
        inst._inner_from_values("cmn hdr", "addr hdr", "path hdr", ext_hdrs)
        # Tests
        super_values.assert_called_once_with(
            inst, "cmn hdr", "addr hdr", "path hdr")
        ntools.eq_(inst.ext_hdrs, ext_hdrs)


class TestSCIONExtPacketInnerPack(object):
    """
    Unit tests for lib.packet.scion.SCIONExtPacket._inner_pack
    """
    @patch("lib.packet.scion.SCIONBasePacket._inner_pack", autospec=True)
    def test(self, super_pack):
        inst = SCIONExtPacket()
        inst._l4_proto = 0x42
        super_pack.return_value = b"super"
        inst.ext_hdrs = []
        for idx, class_, len_, type_ in (
            (0, 0x1, 0x12, 0x0), (1, 0x2, 0x30, 0x11), (2, 0x3, 0x14, 0x1)
        ):
            hdr = create_mock(["hdr_len", "EXT_CLASS", "EXT_TYPE", "pack"])
            hdr.EXT_CLASS = class_
            hdr.hdr_len.return_value = len_
            hdr.EXT_TYPE = type_
            hdr.pack.return_value = ("packed %d" % idx).encode("utf-8")
            inst.ext_hdrs.append(hdr)
        expected = b"".join([
            b"super",
            bytes([0x2, 0x12, 0x0]), b"packed 0",
            bytes([0x3, 0x30, 0x11]), b"packed 1",
            bytes([0x42, 0x14, 0x1]), b"packed 2",
        ])
        # Call
        ntools.eq_(inst._inner_pack(), expected)


class TestSCIONExtPacketGetOffsetLen(object):
    """
    Unit tests for lib.packet.scion.SCIONExtPacket._get_offset_len
    """
    @patch("lib.packet.scion.SCIONBasePacket._get_offset_len", autospec=True)
    def test(self, super_offset):
        inst = SCIONExtPacket()
        inst.ext_hdrs = ["a", "bb", "cccc"]
        super_offset.return_value = 42
        # Call
        ntools.eq_(inst._get_offset_len(), 49)


class TestSCIONExtPacketGetNextHdr(object):
    """
    Unit tests for lib.packet.scion.SCIONExtPacket._get_next_hdr
    """
    def test_no_exts(self):
        inst = SCIONExtPacket()
        inst.ext_hdrs = []
        inst._l4_proto = 42
        # Call
        ntools.eq_(inst._get_next_hdr(), 42)

    def test_with_exts(self):
        inst = SCIONExtPacket()
        inst.ext_hdrs = [create_mock(["EXT_CLASS"]), 0]
        # Call
        ntools.eq_(inst._get_next_hdr(), inst.ext_hdrs[0].EXT_CLASS)


class TestSCIONL4PacketInit(object):
    """
    Unit tests for lib.packet.scion.SCIONL4Packet.__init__
    """
    @patch("lib.packet.scion.SCIONL4Packet._parse", autospec=True)
    @patch("lib.packet.scion.SCIONBasePacket.__init__", autospec=True,
           return_value=None)
    def test_basic(self, super_init, parse):
        inst = SCIONL4Packet()
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.assert_is_none(inst.l4_hdr)
        ntools.assert_false(parse.called)

    @patch("lib.packet.scion.SCIONExtPacket._parse", autospec=True)
    @patch("lib.packet.scion.SCIONBasePacket.__init__", autospec=True,
           return_value=None)
    def test_raw(self, super_init, parse):
        inst = SCIONL4Packet(b"raw")
        # Tests
        parse.assert_called_once_with(inst, b"raw")


class TestSCIONL4PacketInnerParse(object):
    """
    Unit tests for lib.packet.scion.SCIONL4Packet._inner_parse
    """
    @patch("lib.packet.scion.parse_l4_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONExtPacket._inner_parse", autospec=True)
    def test(self, super_parse, parse_l4_hdr):
        inst = SCIONL4Packet()
        inst._l4_proto = 42
        inst.addrs = create_mock(["get_src_addr", "get_dst_addr"])
        data = create_mock()
        parse_l4_hdr.return_value.__len__.return_value = 8
        # Call
        inst._inner_parse(data)
        # Tests
        super_parse.assert_called_once_with(inst, data)
        parse_l4_hdr.assert_called_once_with(
            42, data, src_addr=inst.addrs.get_src_addr.return_value,
            dst_addr=inst.addrs.get_dst_addr.return_value,
        )
        ntools.eq_(inst.l4_hdr, parse_l4_hdr.return_value)


class TestSCIONL4PacketFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONL4Packet.from_values
    """
    @patch("lib.packet.scion.SCIONL4Packet.update", autospec=True)
    @patch("lib.packet.scion.SCIONL4Packet.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONL4Packet._inner_from_values", autospec=True)
    def test_basic(self, inner_values, set_pld, upd_hdrs):
        inst = SCIONL4Packet.from_values("cmn hdr", "addr hdr", "path hdr",
                                         "ext hdrs", "l4 hdr")
        # Tests
        ntools.assert_is_instance(inst, SCIONL4Packet)
        inner_values.assert_called_once_with(
            inst, "cmn hdr", "addr hdr", "path hdr", "ext hdrs", "l4 hdr")
        set_pld.assert_called_once_with(inst, b"")
        upd_hdrs.assert_called_once_with(inst)

    @patch("lib.packet.scion.SCIONL4Packet.update", autospec=True)
    @patch("lib.packet.scion.SCIONL4Packet.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONL4Packet._inner_from_values", autospec=True)
    def test_payload(self, inner_values, set_pld, upd_hdrs):
        inst = SCIONL4Packet.from_values("cmn hdr", "addr hdr", "path hdr",
                                         "ext hdrs", "l4 hdr", "payload")
        # Tests
        set_pld.assert_called_once_with(inst, "payload")


class TestSCIONL4PacketInnerFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONL4Packet._inner_from_values
    """
    @patch("lib.packet.scion.SCIONExtPacket._inner_from_values", autospec=True)
    def test(self, super_values):
        inst = SCIONL4Packet()
        l4_hdr = MagicMock(spec_set=L4HeaderBase)
        l4_hdr.TYPE = 22
        # Call
        inst._inner_from_values("cmn hdr", "addr hdr", "path hdr", "ext hdrs",
                                l4_hdr)
        # Tests
        super_values.assert_called_once_with(
            inst, "cmn hdr", "addr hdr", "path hdr", "ext hdrs")
        ntools.eq_(inst.l4_hdr, l4_hdr)
        ntools.eq_(inst._l4_proto, 22)


class TestSCIONL4PacketInnerPack(object):
    """
    Unit tests for lib.packet.scion.SCIONL4Packet._inner_pack
    """
    @patch("lib.packet.scion.SCIONExtPacket._inner_pack", autospec=True)
    def test(self, super_pack):
        inst = SCIONL4Packet()
        inst.update = create_mock()
        super_pack.return_value = b"super"
        inst.l4_hdr = create_mock(["pack"])
        inst.l4_hdr.pack.return_value = b"l4 hdr"
        # Call
        ntools.eq_(inst._inner_pack(), b"super" b"l4 hdr")
        # Tests
        inst.update.assert_called_once_with()


class TestSCIONL4PacketUpdate(object):
    """
    Unit tests for lib.packet.scion.SCIONL4Packet.update
    """
    @patch("lib.packet.scion.SCIONExtPacket.update", autospec=True)
    def test_no_l4hdr(self, super_update):
        inst = SCIONL4Packet()
        inst._l4_proto = 47
        # Call
        inst.update()
        # Tests
        super_update.assert_called_once_with(inst)
        ntools.eq_(inst._l4_proto, 47)

    @patch("lib.packet.scion.SCIONExtPacket.update", autospec=True)
    def test_l4hdr(self, super_update):
        inst = SCIONL4Packet()
        inst.addrs = create_mock(["get_src_addr", "get_dst_addr"])
        inst._l4_proto = 47
        inst.l4_hdr = create_mock(["TYPE", "update"])
        inst._payload = "payload"
        # Call
        inst.update()
        # Tests
        inst.l4_hdr.update.assert_called_once_with(
            src_addr=inst.addrs.get_src_addr.return_value,
            dst_addr=inst.addrs.get_dst_addr.return_value, payload="payload")
        ntools.eq_(inst._l4_proto, inst.l4_hdr.TYPE)


class TestSCIONL4PacketParsePayload(object):
    """
    Unit tests for lib.packet.scion.SCIONL4Packet.parse_payload
    """
    @patch("lib.packet.scion.parse_pathmgmt_payload", autospec=True)
    @patch("lib.packet.scion.parse_certmgmt_payload", autospec=True)
    @patch("lib.packet.scion.parse_ifid_payload", autospec=True)
    @patch("lib.packet.scion.parse_pcb_payload", autospec=True)
    @patch("lib.packet.scion.Raw", autospec=True)
    def _check_known(self, class_, raw, parse_pcb, parse_ifid, parse_cert,
                     parse_path):
        class_map = {
            PayloadClass.PCB: parse_pcb, PayloadClass.IFID: parse_ifid,
            PayloadClass.CERT: parse_cert, PayloadClass.PATH: parse_path,
        }
        handler = class_map[class_]
        inst = SCIONL4Packet()
        inst._payload = create_mock(["pack"])
        inst.set_payload = create_mock()
        data = create_mock(["pop"])
        data.pop.side_effect = class_, 42
        raw.return_value = data
        # Call
        ntools.eq_(inst.parse_payload(), handler.return_value)
        # Tests
        handler.assert_called_once_with(42, data)
        inst.set_payload.assert_called_once_with(handler.return_value)

    def test_known(self):
        for class_ in (
            PayloadClass.PCB, PayloadClass.IFID,
            PayloadClass.CERT, PayloadClass.PATH,
        ):
            yield self._check_known, class_

    @patch("lib.packet.scion.Raw", autospec=True)
    def test_unknown(self, raw):
        inst = SCIONL4Packet()
        inst._payload = create_mock(["pack"])
        data = create_mock(["pop"])
        data.pop.return_value = 42
        raw.return_value = data
        # Call
        ntools.assert_raises(SCIONParseError, inst.parse_payload)


class TestSCIONL4PacketGetOffsetLen(object):
    """
    Unit tests for lib.packet.scion.SCIONL4Packet._get_offset_len
    """
    @patch("lib.packet.scion.SCIONExtPacket._get_offset_len", autospec=True)
    def test(self, super_offset):
        inst = SCIONL4Packet()
        inst.l4_hdr = create_mock(["__len__"])
        inst.l4_hdr.__len__.return_value = 12
        inst._payload = create_mock(["METADATA_LEN"])
        inst._payload.METADATA_LEN = 2
        super_offset.return_value = 42
        # Call
        ntools.eq_(inst._get_offset_len(), 56)


class TestIFIDPayloadInit(object):
    """
    Unit tests for lib.packet.scion.IFIDPayload.__init__
    """
    @patch("lib.packet.scion.IFIDPayload._parse", autospec=True)
    @patch("lib.packet.scion.SCIONPayloadBase.__init__", autospec=True)
    def test_full(self, super_init, parse):
        inst = IFIDPayload("data")
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.eq_(inst.reply_id, 0)
        ntools.assert_is_none(inst.request_id)
        parse.assert_called_once_with(inst, "data")


class TestIFIDPayloadParse(object):
    """
    Unit tests for lib.packet.scion.IFIDPayload._parse
    """
    @patch("lib.packet.scion.Raw", autospec=True)
    def test(self, raw):
        inst = IFIDPayload()
        data = create_mock(["pop"])
        data.pop.return_value = bytes.fromhex('0102 0304')
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "IFIDPayload", inst.LEN)
        ntools.eq_(inst.reply_id, 0x0102)
        ntools.eq_(inst.request_id, 0x0304)


class TestIFIDPayloadFromValues(object):
    """
    Unit tests for lib.packet.scion.IFIDPayload.from_values
    """
    def test(self):
        inst = IFIDPayload.from_values(42)
        # Tests
        ntools.assert_is_instance(inst, IFIDPayload)
        ntools.eq_(inst.request_id, 42)


class TestIFIDPayloadPack(object):
    """
    Unit tests for lib.packet.scion.IFIDPayload.pack
    """
    def test(self):
        inst = IFIDPayload()
        inst.reply_id = 0x0102
        inst.request_id = 0x0304
        expected = bytes.fromhex('0102 0304')
        # Call
        ntools.eq_(inst.pack(), expected)


class TestBuildBaseHdrs(object):
    """
    Unit tests for lib.packet.scion.build_base_hdrs
    """
    @patch("lib.packet.scion.SCIONAddrHdr.from_values",
           new_callable=create_mock)
    @patch("lib.packet.scion.SCIONCommonHdr.from_values",
           new_callable=create_mock)
    def test(self, cmn_hdr, addr_hdr):
        src = create_mock(["host_addr"])
        src.host_addr = create_mock(["TYPE"])
        dst = create_mock(["host_addr"])
        dst.host_addr = create_mock(["TYPE"])
        # Call
        ntools.eq_(build_base_hdrs(src, dst),
                   (cmn_hdr.return_value, addr_hdr.return_value))
        # Tests
        cmn_hdr.assert_called_once_with(src.host_addr.TYPE, dst.host_addr.TYPE)
        addr_hdr.assert_called_once_with(src, dst)


class TestParseIfidPayload(object):
    """
    Unit tests for lib.packet.scion.parse_ifid_payload
    """
    @patch("lib.packet.scion.IFIDPayload", autospec=True)
    def test_success(self, ifid_pld):
        data = create_mock(["pop"])
        # Call
        ntools.eq_(parse_ifid_payload(IFIDType.PAYLOAD, data),
                   ifid_pld.return_value)

    def test_unknown(self):
        ntools.assert_raises(SCIONParseError, parse_ifid_payload, 99, "data")

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
