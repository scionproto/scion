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
import capnp  # noqa
import nose
import nose.tools as ntools

# SCION
from lib.defines import LINE_LEN
from lib.errors import SCIONIndexError, SCIONParseError
from lib.packet.ext_hdr import ExtensionHeader
from lib.packet.host_addr import HostAddrInvalidType
from lib.packet.packet_base import L4HeaderBase, PayloadRaw
from lib.packet.path import SCIONPath
from lib.packet.scion import (
    SCIONAddrHdr,
    SCIONBasePacket,
    SCIONCommonHdr,
    SCIONExtPacket,
    SCIONL4Packet,
    build_base_hdrs,
)
from lib.packet.scion_addr import ISD_AS
from lib.packet.scmp.errors import (
    SCMPBadDstType,
    SCMPBadEnd2End,
    SCMPBadHOFOffset,
    SCMPBadHopByHop,
    SCMPBadIOFOffset,
    SCMPBadPktLen,
    SCMPBadSrcType,
    SCMPBadVersion,
)
from lib.types import (
    AddrType,
    ExtHopByHopType,
    ExtensionClass,
    L4Proto,
)
from test.testcommon import assert_these_calls, create_mock, create_mock_full


class TestSCIONCommonHdrParse(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr._parse
    """
    def _setup(self, first_b=0b00001111):
        inst = SCIONCommonHdr()
        data = create_mock(["pop"])
        data.pop.return_value = bytes([first_b, 0b00111111]) + \
            bytes.fromhex('0304 04 07 08 09')
        return inst, data

    @patch("lib.packet.scion.Raw", autospec=True)
    def test_bad_ver(self, raw):
        inst, data = self._setup(0b11110000)
        raw.return_value = data
        # Call
        ntools.assert_raises(SCMPBadVersion, inst._parse, "data")

    @patch("lib.packet.scion.SCIONAddrHdr.calc_lens", new_callable=create_mock)
    @patch("lib.packet.scion.Raw", autospec=True)
    def test_success(self, raw, calc_lens):
        inst, data = self._setup()
        raw.return_value = data
        calc_lens.return_value = 24, 0
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.LEN)
        ntools.eq_(inst.total_len, 0x0304)
        ntools.eq_(inst.hdr_len, 0x04)
        ntools.eq_(inst.hdr_len_bytes(), 0x20)
        ntools.eq_(inst.next_hdr, 0x09)
        ntools.eq_(inst.version, 0b0)
        ntools.eq_(inst.dst_addr_type, 0b111100)
        ntools.eq_(inst.src_addr_type, 0b111111)
        calc_lens.assert_called_once_with(0b111100, 0b111111)
        ntools.eq_(inst.addrs_len, 24)
        ntools.eq_(inst._iof_idx, 3)
        ntools.eq_(inst._hof_idx, 4)

    @patch("lib.packet.scion.SCIONAddrHdr.calc_lens", new_callable=create_mock)
    @patch("lib.packet.scion.Raw", autospec=True)
    def test_bad_len(self, raw, calc_lens):
        inst, data = self._setup()
        calc_lens.return_value = 32, 0
        raw.return_value = data
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse, "data")


class TestSCIONCommonHdrFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.from_values
    """
    @patch("lib.packet.scion.SCIONAddrHdr.calc_lens", new_callable=create_mock)
    def test(self, calc_lens):
        # Setup
        dst_type = 1
        src_type = 2
        calc_lens.return_value = 24, 0
        hdr_len = (SCIONCommonHdr.LEN + 24)//8
        # Call
        inst = SCIONCommonHdr.from_values(dst_type, src_type, 3)
        # Tests
        ntools.assert_is_instance(inst, SCIONCommonHdr)
        ntools.eq_(inst.dst_addr_type, dst_type)
        ntools.eq_(inst.src_addr_type, src_type)
        calc_lens.assert_called_once_with(dst_type, src_type)
        ntools.eq_(inst.addrs_len, 24)
        ntools.eq_(inst.next_hdr, 3)
        ntools.eq_(inst.hdr_len, hdr_len)
        ntools.eq_(inst.total_len, hdr_len * 8)


class TestSCIONCommonHdrPack(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.pack
    """
    def test(self):
        inst = SCIONCommonHdr()
        inst.version = 0b1111
        inst.dst_addr_type = 0b000000
        inst.src_addr_type = 0b111111
        inst.addrs_len = 24
        inst.total_len = 0x0304
        inst.hdr_len = 0x05
        inst._iof_idx = 0x03
        inst._hof_idx = 0x04
        inst.next_hdr = 0x09
        expected = b"".join([
            bytes([0b11110000, 0b00111111]),
            bytes.fromhex('0304 05 07 08 09'),
        ])
        # Call
        ntools.eq_(inst.pack(), expected)


class TestSCIONCommonHdrValidate(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.validate
    """
    def _check(self, pkt_len, path_len, expected, iof=1, hof=3):
        inst = SCIONCommonHdr()
        inst.total_len = 10
        inst._iof_idx = iof
        inst._hof_idx = hof
        # Call
        if expected is None:
            inst.validate(pkt_len, path_len)
            return
        ntools.assert_raises(expected, inst.validate, pkt_len, path_len)

    def test_total_len(self):
        for pkt_len, expected in (
            (0, SCMPBadPktLen), (9, SCMPBadPktLen),
            (10, None), (11, SCMPBadPktLen),
        ):
            yield self._check, pkt_len, 10, expected

    def test_empty_path(self):
        for iof_idx, hof_idx, expected in (
            (0, 0, None), (1, 0, SCMPBadIOFOffset),
            (0, 1, SCMPBadHOFOffset), (1, 1, SCMPBadIOFOffset),
        ):
            yield self._check, 10, 0, expected, iof_idx, hof_idx

    def test_with_path(self):
        for hof_idx, expected in (
            (0, SCMPBadHOFOffset), (1, None)
        ):
            yield self._check, 10, 1, expected, 0, hof_idx


class TestSCIONCommonHdrStr(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.__str__
    """
    @patch("lib.packet.scion.haddr_get_type", autospec=True)
    def test(self, get_type):
        inst = SCIONCommonHdr()
        inst.dst_addr_type = 0b111111
        inst.src_addr_type = 0b000000
        inst.version = 0b1111
        inst.total_len = 0x304
        inst.hdr_len = 0x8
        inst._iof_idx = 3
        inst._hof_idx = 4
        inst.next_hdr = 0x7
        addr_type = create_mock(['name'])
        addr_type.name.return_value = "name"
        get_type.return_value = addr_type
        # Call
        str(inst)


class TestSCIONAddrHdrParse(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr._parse
    """
    def _setup(self, src_type, haddr, saddr):
        inst = SCIONAddrHdr()
        inst.calc_lens = create_mock()
        inst.update = create_mock()
        data = create_mock_full({
            "pop()...": ("1-1", "2-2", "dst host", "src host"),
        })
        src_host = create_mock_full({"TYPE": src_type})
        src = create_mock_full({"host": src_host})
        haddr.side_effect = (
            create_mock_full({"LEN": 12}, return_value="dst haddr"),
            create_mock_full({"LEN": 34}, return_value="src haddr"),
        )
        saddr.side_effect = "dst", src
        return inst, data, src, "dst"

    @patch("lib.packet.scion.SCIONAddr.from_values", new_callable=create_mock)
    @patch("lib.packet.scion.haddr_get_type", autospec=True)
    @patch("lib.packet.scion.Raw", autospec=True)
    def test_success(self, raw, haddr, saddr):
        inst, data, src, dst = self._setup(AddrType.IPV4, haddr, saddr)
        raw.return_value = data
        # Call
        inst._parse(1, 2, "data")
        # Tests
        inst.calc_lens.assert_called_once_with(1, 2)
        raw.assert_called_once_with(
            "data", inst.NAME, inst.calc_lens.return_value[0])
        assert_these_calls(data.pop, [call(ISD_AS.LEN), call(ISD_AS.LEN), call(12), call(34)])
        assert_these_calls(haddr, [call(1), call(2)])
        assert_these_calls(saddr, [call(ISD_AS("1-1"), "dst haddr"),
                                   call(ISD_AS("2-2"), "src haddr")])
        ntools.eq_(inst.dst, dst)
        ntools.eq_(inst.src, src)
        inst.update.assert_called_once_with()

    @patch("lib.packet.scion.SCIONAddr.from_values", new_callable=create_mock)
    @patch("lib.packet.scion.haddr_get_type", autospec=True)
    @patch("lib.packet.scion.Raw", autospec=True)
    def test_fail(self, raw, haddr, saddr):
        inst, data, src, dst = self._setup(AddrType.SVC, haddr, saddr)
        raw.return_value = data
        # Call
        ntools.assert_raises(SCMPBadSrcType, inst._parse, 1, 2, "data")


class TestSCIONAddrHdrPack(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr.pack
    """
    def test(self):
        inst = SCIONAddrHdr()
        inst.update = create_mock()
        dst_ia = create_mock_full({"pack()": b"dsIA"})
        dst_host = create_mock_full({"pack()": b"dst H"})
        inst.dst = create_mock_full({"isd_as": dst_ia, "host": dst_host})
        src_ia = create_mock_full({"pack()": b"srIA"})
        src_host = create_mock_full({"pack()": b"src H"})
        inst.src = create_mock_full({"isd_as": src_ia, "host": src_host})
        inst._total_len = 24
        inst._pad_len = 6
        expected = b"dsIA" b"srIA" b"dst H" b"src H"
        expected += bytes(inst._pad_len)
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        inst.update.assert_called_once_with()


class TestSCIONAddrHdrUpdate(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr.update
    """
    def test(self):
        inst = SCIONAddrHdr()
        inst.calc_lens = create_mock_full(return_value=(1, 3))
        inst.src = create_mock_full({"host": create_mock(["TYPE"])})
        inst.dst = create_mock_full({"host": create_mock(["TYPE"])})
        # Call
        inst.update()
        # Tests
        inst.calc_lens.assert_called_once_with(
            inst.dst.host.TYPE, inst.src.host.TYPE)
        ntools.eq_(inst._total_len, 1)
        ntools.eq_(inst._pad_len, 3)


class TestSCIONAddrHdrCalcLens(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr.calc_lens
    """
    @patch("lib.packet.scion.calc_padding", autospec=True)
    @patch("lib.packet.scion.SCIONAddr.calc_len", new_callable=create_mock)
    def _check(self, type_lens, exp_total, exp_pad, calc_len, calc_padding):
        calc_len.side_effect = type_lens
        calc_padding.return_value = exp_pad
        # Call
        results = SCIONAddrHdr.calc_lens(1, 2)
        # Tests
        assert_these_calls(calc_len, [call(1), call(2)])
        calc_padding.assert_called_once_with(
            sum(type_lens), SCIONAddrHdr.BLK_SIZE)
        ntools.eq_(results, (exp_total, exp_pad))

    def test(self):
        for type_lens, exp_total, exp_pad in (
            ((8, 16), 24, 0),  # no padding required
            ((8, 19), 32, 5),  # padding required
        ):
            yield self._check, type_lens, exp_total, exp_pad

    @patch("lib.packet.scion.SCIONAddr.calc_len", new_callable=create_mock)
    def test_bad_dst_type(self, calc_len):
        calc_len.side_effect = HostAddrInvalidType
        # Call
        ntools.assert_raises(SCMPBadDstType, SCIONAddrHdr.calc_lens, 1, 2)

    @patch("lib.packet.scion.SCIONAddr.calc_len", new_callable=create_mock)
    def test_bad_src_type(self, calc_len):
        calc_len.side_effect = "data len", HostAddrInvalidType
        # Call
        ntools.assert_raises(SCMPBadSrcType, SCIONAddrHdr.calc_lens, 1, 2)


class TestSCIONAddrHdrReverse(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr.reverse
    """
    def test(self):
        inst = SCIONAddrHdr()
        inst.update = create_mock()
        inst.src = "src"
        inst.dst = "dst"
        # Call
        inst.reverse()
        # Tests
        ntools.eq_(inst.src, "dst")
        ntools.eq_(inst.dst, "src")
        inst.update.assert_called_once_with()


class TestSCIONAddrHdrLen(object):
    """
    Unit tests for lib.packet.scion.SCIONAddrHdr.__len__
    """
    def test(self):
        inst = SCIONAddrHdr()
        inst._total_len = 42
        # Call
        ntools.eq_(len(inst), 42)


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
        raw.assert_called_once_with(b"data", inst.NAME, inst.MIN_LEN, min_=True)
        inst._inner_parse.assert_called_once_with(data)
        pld_raw.assert_called_once_with(data.get.return_value)
        inst.set_payload.assert_called_once_with(pld_raw.return_value)


class TestSCIONBasePacketParseAddrs(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket._parse_addrs
    """
    @patch("lib.packet.scion.SCIONAddrHdr", autospec=True)
    def test(self, addr_hdr):
        inst = SCIONBasePacket()
        cmn_hdr = create_mock(["addrs_len", "dst_addr_type", "src_addr_type"])
        inst.cmn_hdr = cmn_hdr
        data = create_mock(["get", "pop"])
        # Call
        inst._parse_addrs(data)
        # Tests
        addr_hdr.assert_called_once_with((
            cmn_hdr.dst_addr_type, cmn_hdr.src_addr_type,
            data.get.return_value))
        ntools.eq_(inst.addrs, addr_hdr.return_value)
        data.pop.assert_called_once_with(addr_hdr.__len__.return_value)


class TestSCIONBasePacketParsePath(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket._parse_path
    """
    def _setup(self, data_offset=10, hdr_len_bytes=20):
        inst = SCIONBasePacket()
        inst.cmn_hdr = create_mock(["get_of_idxs", "hdr_len", "hdr_len_bytes"])
        inst.cmn_hdr.get_of_idxs.return_value = "iof", "hof"
        inst.cmn_hdr.hdr_len = hdr_len_bytes // LINE_LEN
        inst.cmn_hdr.hdr_len_bytes = lambda: hdr_len_bytes
        data = create_mock(["__len__", "get", "offset", "pop"])
        data.__len__.return_value = 40 - data_offset
        data.offset.return_value = data_offset
        return inst, data

    @patch("lib.packet.scion.parse_path", autospec=True)
    def test_too_short(self, parse_path):
        inst, data = self._setup(hdr_len_bytes=9)
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse_path, data)

    @patch("lib.packet.scion.parse_path", autospec=True)
    def test_too_long(self, parse_path):
        inst, data = self._setup(hdr_len_bytes=50)
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse_path, data)

    @patch("lib.packet.scion.parse_path", autospec=True)
    def test_success(self, parse_path):
        inst, data = self._setup()
        path = create_mock(["__len__", "set_of_idxs"])
        path.__len__.return_value = 42
        parse_path.return_value = path
        # Call
        inst._parse_path(data)
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
    def test(self, inner_values, pld_raw, set_pld, update):
        inst = SCIONBasePacket.from_values("cmn hdr", "addr hdr", "path hdr")
        # Tests
        ntools.assert_is_instance(inst, SCIONBasePacket)
        inner_values.assert_called_once_with(
            inst, "cmn hdr", "addr hdr", "path hdr")
        pld_raw.assert_called_once_with()
        set_pld.assert_called_once_with(inst, pld_raw.return_value)
        update.assert_called_once_with(inst)


class TestSCIONBasePacketInnerFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket._inner_from_values
    """
    def test(self):
        inst = SCIONBasePacket()
        cmn_hdr = MagicMock(spec_set=SCIONCommonHdr)
        addr_hdr = MagicMock(spec_set=SCIONAddrHdr)
        path_hdr = MagicMock(spec_set=SCIONPath)
        # Call
        inst._inner_from_values(cmn_hdr, addr_hdr, path_hdr)


class TestSCIONBasePacketPack(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket.pack
    """
    @patch("lib.packet.scion.SCIONBasePacket.update", autospec=True)
    def test(self, update):
        hdr_exp = b"cmn hdr" b"addrs" b"path"
        total_exp = hdr_exp + b"inner pack"
        inst = SCIONBasePacket()
        inst.update = create_mock()
        inst.cmn_hdr = create_mock(["hdr_len_bytes", "pack", "total_len"])
        inst.cmn_hdr.hdr_len_bytes = lambda: len(hdr_exp)
        inst.cmn_hdr.total_len = len(total_exp)
        inst.cmn_hdr.pack.return_value = b"cmn hdr"
        inst.addrs = create_mock(["pack"])
        inst.addrs.pack.return_value = b"addrs"
        inst.path = create_mock(["pack"])
        inst.path.pack.return_value = b"path"
        inst._inner_pack = create_mock()
        inst._inner_pack.return_value = b"inner pack"
        # Call
        ntools.eq_(inst.pack(), total_exp)
        # Tests
        inst.update.assert_called_once_with()


class TestSCIONBasePacketValidate(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket.validate
    """
    def test(self):
        inst = SCIONBasePacket()
        inst.path = "path"
        inst.cmn_hdr = create_mock(["validate"])
        inst.addrs = create_mock(["validate"])
        inst._validate_of_idxes = create_mock()
        inst._payload = PayloadRaw()
        # Call
        inst.validate("pkt len")
        # Tests
        inst.cmn_hdr.validate.assert_called_once_with("pkt len", 4)
        inst.addrs.validate.assert_called_once_with()
        inst._validate_of_idxes.assert_called_once_with()


class TestSCIONBasePacketValidateOFIdxes(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket._validate_of_idxes
    """
    def test_bad_iof(self):
        inst = SCIONBasePacket()
        inst.path = create_mock(["get_iof"])
        inst.path.get_iof.side_effect = SCIONIndexError
        # Call
        ntools.assert_raises(SCMPBadIOFOffset, inst._validate_of_idxes)

    def test_bad_hof(self):
        inst = SCIONBasePacket()
        inst.path = create_mock(["get_iof", "get_hof"])
        inst.path.get_hof.side_effect = SCIONIndexError
        # Call
        ntools.assert_raises(SCMPBadHOFOffset, inst._validate_of_idxes)


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
            "hdr_len_bytes", "bytes_to_hdr_len", "total_len", "set_of_idxs", "next_hdr", "update",
        ])
        cmn_hdr.__len__.return_value = SCIONCommonHdr.LEN
        cmn_hdr.bytes_to_hdr_len = lambda x: x//8
        cmn_hdr.hdr_len_bytes.return_value = 32
        addrs = create_mock(["__len__", "src_type", "dst_type"])
        addrs.__len__.return_value = 16
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
        ntools.eq_(cmn_hdr.src_addr_type, addrs.src_type.return_value)
        ntools.eq_(cmn_hdr.dst_addr_type, addrs.dst_type.return_value)
        ntools.eq_(cmn_hdr.addrs_len, 16)
        ntools.eq_(cmn_hdr.hdr_len, (8 + 16 + 8)//8)
        ntools.eq_(cmn_hdr.total_len, 32 + 42)
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


class TestSCIONBasePacketConvertToSCMPError(object):
    """
    Unit tests for lib.packet.scion.SCIONBasePacket.convert_to_scmp_error
    """
    @patch("lib.packet.scion.SCMPHeader.from_values", new_callable=create_mock)
    @patch("lib.packet.scion.SCMPPayload.from_pkt", new_callable=create_mock)
    @patch("lib.packet.scion.SCMPExt.from_values", new_callable=create_mock)
    def test(self, ext_fv, pld_fp, hdr_fv):
        inst = SCIONBasePacket()
        inst.addrs = create_mock(["dst", "src"])
        scmp_ext = create_mock(["EXT_TYPE"])
        scmp_ext.EXT_TYPE = ExtHopByHopType.SCMP
        inst.ext_hdrs = [scmp_ext, "ext1", "ext2", "ext3", "ext4"]
        inst.set_payload = create_mock()
        # Call
        inst.convert_to_scmp_error(
            "addr", "class", "type", "pkt", "arg1", "arg2", hopbyhop="hbh",
            kwarg1="kwval1")
        # Tests
        ext_fv.assert_called_once_with(hopbyhop="hbh")
        ntools.eq_(inst.ext_hdrs, [ext_fv.return_value, "ext1", "ext2", "ext3"])
        pld_fp.assert_called_once_with(
            "class", "type", "pkt", "arg1", "arg2", kwarg1="kwval1")
        hdr_fv.assert_called_once_with(
            "addr", inst.addrs.dst, "class", "type")
        ntools.eq_(inst.l4_hdr, hdr_fv.return_value)
        inst.set_payload.assert_called_once_with(pld_fp.return_value)


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
            (0, 0x1, 0x0, 0x0), (1, 0x2, 0x1, 0x11), (2, 0x3, 0x2, 0x1)
        ):
            hdr = create_mock(["hdr_len", "EXT_CLASS", "EXT_TYPE", "pack"])
            hdr.EXT_CLASS = class_
            hdr.hdr_len.return_value = len_
            hdr.EXT_TYPE = type_
            hdr.pack.return_value = bytes(
                range(5+len_*ExtensionHeader.LINE_LEN))
            inst.ext_hdrs.append(hdr)
        expected = b"".join([
            b"super",
            bytes([0x2, 0x0, 0x0]), bytes(range(5)),
            bytes([0x3, 0x1, 0x11]), bytes(range(13)),
            bytes([0x42, 0x2, 0x1]), bytes(range(21)),
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


class TestSCIONExtPacketValidate(object):
    """
    Unit tests for lib.packet.scion.SCIONExtPacket.validate
    """
    @patch("lib.packet.scion.SCIONBasePacket.validate", autospec=True)
    def test_no_unknown(self, super_val):
        inst = SCIONExtPacket()
        # Call
        ntools.ok_(inst.validate("pkt len"))
        # Tests
        super_val.assert_called_once_with(inst, "pkt len")

    @patch("lib.packet.scion.SCIONBasePacket.validate", autospec=True)
    def test_unknown_hbh(self, super_val):
        inst = SCIONExtPacket()
        inst._unknown_exts = {ExtensionClass.HOP_BY_HOP: [1]}
        # Call
        ntools.assert_raises(SCMPBadHopByHop, inst.validate, "pkt len")

    @patch("lib.packet.scion.SCIONBasePacket.validate", autospec=True)
    def test_unknown_e2e(self, super_val):
        inst = SCIONExtPacket()
        inst._unknown_exts = {ExtensionClass.END_TO_END: [1]}
        # Call
        ntools.assert_raises(SCMPBadEnd2End, inst.validate, "pkt len")


class TestSCIONL4PacketInnerParse(object):
    """
    Unit tests for lib.packet.scion.SCIONL4Packet._inner_parse
    """
    @patch("lib.packet.scion.parse_l4_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONExtPacket._inner_parse", autospec=True)
    def test(self, super_parse, parse_l4_hdr):
        inst = SCIONL4Packet()
        inst._l4_proto = 42
        inst.addrs = create_mock(["src", "dst"])
        data = create_mock()
        parse_l4_hdr.return_value.__len__.return_value = 8
        # Call
        inst._inner_parse(data)
        # Tests
        super_parse.assert_called_once_with(inst, data)
        parse_l4_hdr.assert_called_once_with(
            42, data, src=inst.addrs.src, dst=inst.addrs.dst,
        )
        ntools.eq_(inst.l4_hdr, parse_l4_hdr.return_value)


class TestSCIONL4PacketFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONL4Packet.from_values
    """
    @patch("lib.packet.scion.SCIONL4Packet.update", autospec=True)
    @patch("lib.packet.scion.SCIONL4Packet.set_payload", autospec=True)
    @patch("lib.packet.scion.PayloadRaw", autospec=True)
    @patch("lib.packet.scion.SCIONL4Packet._inner_from_values", autospec=True)
    def test(self, inner_values, pldraw, set_pld, upd_hdrs):
        inst = SCIONL4Packet.from_values("cmn hdr", "addr hdr", "path hdr",
                                         "ext hdrs", "l4 hdr")
        # Tests
        ntools.assert_is_instance(inst, SCIONL4Packet)
        inner_values.assert_called_once_with(
            inst, "cmn hdr", "addr hdr", "path hdr", "ext hdrs", "l4 hdr")
        set_pld.assert_called_once_with(inst, pldraw.return_value)
        upd_hdrs.assert_called_once_with(inst)


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
    @patch("lib.packet.scion.SCIONExtPacket._pack_payload", autospec=True)
    @patch("lib.packet.scion.SCIONExtPacket._inner_pack", autospec=True)
    def test(self, super_pack, super_pld):
        inst = SCIONL4Packet()
        inst.update = create_mock()
        super_pack.return_value = b"super"
        super_pld.return_value = b"pld"
        inst.l4_hdr = create_mock(["pack"])
        inst.l4_hdr.pack.return_value = b"l4 hdr"
        # Call
        ntools.eq_(inst._inner_pack(), b"super" b"l4 hdr" b"pld")
        # Tests
        inst.update.assert_called_once_with()
        inst.l4_hdr.pack.assert_called_once_with(b"pld")


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
        inst.addrs = create_mock(["src", "dst"])
        inst._l4_proto = 47
        inst.l4_hdr = create_mock(["TYPE", "update"])
        # Call
        inst.update()
        # Tests
        inst.l4_hdr.update.assert_called_once_with(
            src=inst.addrs.src, dst=inst.addrs.dst)
        ntools.eq_(inst._l4_proto, inst.l4_hdr.TYPE)


class TestSCIONL4PacketParsePayload(object):
    """
    Unit tests for lib.packet.scion.SCIONL4Packet.parse_payload
    """
    def _setup(self, l4_type):
        inst = SCIONL4Packet()
        inst._parse_pld_ctrl = create_mock()
        inst._parse_pld_ctrl.return_value = "pld ctrl"
        inst._parse_pld_scmp = create_mock()
        inst._parse_pld_scmp.return_value = "pld scmp"
        inst.set_payload = create_mock()
        inst._payload = create_mock(["pack"])
        if l4_type == L4Proto.UDP:
            inst.l4_hdr = create_mock_full({"TYPE": l4_type})
        elif l4_type == L4Proto.SCMP:
            inst.l4_hdr = create_mock_full({"TYPE": l4_type,
                                            "class_": "scmp_class", "type": "scmp_type"})
        return inst

    def test_non_l4(self):
        inst = self._setup(None)
        # Call
        ntools.assert_raises(SCIONParseError, inst.parse_payload)

    @patch("lib.packet.scion.SCMPPayload", autospec=True)
    @patch("lib.packet.scion.CtrlPayload", autospec=True)
    def _check_l4(self, l4_type, ctrlp, scmpp):
        inst = self._setup(l4_type)
        inst._payload = create_mock_full({"pack()": b"praw"})
        # Call
        ret = inst.parse_payload()
        # Tests
        if l4_type == L4Proto.UDP:
            expected = ctrlp.from_raw.return_value
            ctrlp.from_raw.assert_called_once_with(b"praw")
        elif l4_type == L4Proto.SCMP:
            expected = scmpp.return_value
            scmpp.assert_called_once_with(("scmp_class", "scmp_type", b"praw"))
        inst.set_payload.assert_called_once_with(expected)
        ntools.assert_equal(ret, expected)

    def test_l4(self):
        for l4_type in L4Proto.UDP, L4Proto.SCMP:
            yield self._check_l4, l4_type


class TestSCIONL4PacketGetOffsetLen(object):
    """
    Unit tests for lib.packet.scion.SCIONL4Packet._get_offset_len
    """
    @patch("lib.packet.scion.SCIONExtPacket._get_offset_len", autospec=True)
    def test(self, super_offset):
        inst = SCIONL4Packet()
        inst.l4_hdr = create_mock(["total_len"])
        inst.l4_hdr.total_len = 12
        super_offset.return_value = 42
        # Call
        ntools.eq_(inst._get_offset_len(), 54)


class TestBuildBaseHdrs(object):
    """
    Unit tests for lib.packet.scion.build_base_hdrs
    """
    @patch("lib.packet.scion.SCIONAddrHdr.from_values",
           new_callable=create_mock)
    @patch("lib.packet.scion.SCIONCommonHdr.from_values",
           new_callable=create_mock)
    def test(self, cmn_hdr, addr_hdr):
        dst = create_mock(["host"])
        dst.host = create_mock(["TYPE"])
        src = create_mock(["host"])
        src.host = create_mock(["TYPE"])
        # Call
        ntools.eq_(build_base_hdrs(dst, src),
                   (cmn_hdr.return_value, addr_hdr.return_value))
        # Tests
        cmn_hdr.assert_called_once_with(dst.host.TYPE, src.host.TYPE,
                                        L4Proto.UDP)
        addr_hdr.assert_called_once_with(dst, src)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
