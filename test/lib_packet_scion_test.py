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
from lib.packet.ext_hdr import ExtensionHeader
from lib.packet.opaque_field import (
    OpaqueField,
    OpaqueFieldType as OFT
)
from lib.packet.path import PathBase
from lib.packet.scion import (
    CertChainReply,
    CertChainRequest,
    IFIDPacket,
    get_type,
    SCIONCommonHdr,
    SCIONHeader,
    SCIONPacket,
    PacketType,
    TRCReply,
    TRCRequest
)
from lib.packet.scion_addr import ISD_AD, SCIONAddr


class TestGetType(object):
    """
    Unit tests for lib.packet.scion.get_type
    """
    @patch("lib.packet.scion.PacketType", autospec=True)
    def test_in_src(self, packet_type):
        pkt = MagicMock(spec_set=['hdr'])
        pkt.hdr = MagicMock(spec_set=['src_addr'])
        pkt.hdr.src_addr = MagicMock(spec_set=['host_addr'])
        pkt.hdr.src_addr.host_addr = 'src_addr'
        packet_type.SRC = ['src_addr']
        ntools.eq_(get_type(pkt), 'src_addr')

    @patch("lib.packet.scion.PacketType", autospec=True)
    def test_in_dst(self, packet_type):
        pkt = MagicMock(spec_set=['hdr'])
        pkt.hdr = MagicMock(spec_set=['src_addr', 'dst_addr'])
        pkt.hdr.dst_addr = MagicMock(spec_set=['host_addr'])
        pkt.hdr.dst_addr.host_addr = 'dst_addr'
        packet_type.SRC = []
        packet_type.DST = ['dst_addr']
        ntools.eq_(get_type(pkt), 'dst_addr')

    @patch("lib.packet.scion.PacketType", autospec=True)
    def test_in_none(self, packet_type):
        pkt = MagicMock(spec_set=['hdr'])
        pkt.hdr = MagicMock(spec_set=['src_addr', 'dst_addr'])
        packet_type.SRC = []
        packet_type.DST = []
        ntools.eq_(get_type(pkt), packet_type.DATA)


class TestSCIONCommonHdrInit(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.__init__
    """
    @patch("lib.packet.scion.HeaderBase.__init__", autospec=True)
    def test_basic(self, init):
        hdr = SCIONCommonHdr()
        init.assert_called_once_with(hdr)
        ntools.eq_(hdr.version, 0)
        ntools.eq_(hdr.src_addr_len, 0)
        ntools.eq_(hdr.dst_addr_len, 0)
        ntools.eq_(hdr.total_len, 0)
        ntools.eq_(hdr.curr_iof_p, 0)
        ntools.eq_(hdr.curr_of_p, 0)
        ntools.eq_(hdr.next_hdr, 0)
        ntools.eq_(hdr.hdr_len, 0)

    @patch("lib.packet.scion.SCIONCommonHdr.parse", autospec=True)
    def test_with_args(self, parse):
        hdr = SCIONCommonHdr('data')
        parse.assert_called_once_with(hdr, 'data')


class TestSCIONCommonHdrFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.from_values
    """
    def test(self):
        # called with args (src_addr_len, dst_addr_len, next_hdr)
        hdr = SCIONCommonHdr.from_values(1, 2, 3)
        ntools.assert_is_instance(hdr, SCIONCommonHdr)
        ntools.eq_(hdr.src_addr_len, 1)
        ntools.eq_(hdr.dst_addr_len, 2)
        ntools.eq_(hdr.next_hdr, 3)
        ntools.eq_(hdr.curr_of_p, 1 + 2)
        ntools.eq_(hdr.curr_iof_p, 1 + 2)
        ntools.eq_(hdr.hdr_len, SCIONCommonHdr.LEN + 1 + 2)
        ntools.eq_(hdr.total_len, SCIONCommonHdr.LEN + 1 + 2)


class TestSCIONCommonHdrParse(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.parse
    """
    def test_wrong_type(self):
        hdr = SCIONCommonHdr()
        ntools.assert_raises(AssertionError, hdr.parse, 123)

    def test_bad_length(self):
        hdr = SCIONCommonHdr()
        dlen = SCIONCommonHdr.LEN - 1
        hdr.parse(b'\x00' * dlen)
        ntools.assert_false(hdr.parsed)

    def test_full(self):
        hdr = SCIONCommonHdr()
        data = bytes([0b11110000, 0b00111111]) + \
            bytes.fromhex('0304 05 06 07 08')
        hdr.parse(data)
        ntools.eq_(hdr.total_len, 0x0304)
        ntools.eq_(hdr.curr_iof_p, 0x05)
        ntools.eq_(hdr.curr_of_p, 0x06)
        ntools.eq_(hdr.next_hdr, 0x07)
        ntools.eq_(hdr.hdr_len, 0x08)
        ntools.eq_(hdr.version, 0b1111)
        ntools.eq_(hdr.src_addr_len, 0b000000)
        ntools.eq_(hdr.dst_addr_len, 0b111111)
        ntools.assert_true(hdr.parsed)


class TestSCIONCommonHdrPack(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.pack
    """
    def test(self):
        hdr = SCIONCommonHdr()
        hdr.version = 0b1111
        hdr.src_addr_len = 0b000000
        hdr.dst_addr_len = 0b111111
        hdr.total_len = 0x304
        hdr.curr_iof_p = 0x5
        hdr.curr_of_p = 0x6
        hdr.next_hdr = 0x7
        hdr.hdr_len = 0x8
        packed = bytes([0b11110000, 0b00111111]) + \
            bytes.fromhex('0304 05 06 07 08')
        ntools.eq_(hdr.pack(), packed)


class TestSCIONHeaderInit(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.__init__
    """
    @patch("lib.packet.scion.HeaderBase.__init__", autospec=True)
    def test_basic(self, init):
        hdr = SCIONHeader()
        init.assert_called_once_with(hdr)
        ntools.assert_is_none(hdr.common_hdr)
        ntools.assert_is_none(hdr.src_addr)
        ntools.assert_is_none(hdr.dst_addr)
        ntools.assert_is_none(hdr._path)
        ntools.eq_(hdr._extension_hdrs, [])

    @patch("lib.packet.scion.SCIONHeader.parse", autospec=True)
    def test_with_args(self, parse):
        hdr = SCIONHeader('data')
        parse.assert_called_once_with(hdr, 'data')


class TestSCIONHeaderFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.from_values
    """
    def test_bad_src(self):
        dst = MagicMock(spec_set=SCIONAddr)
        ntools.assert_raises(AssertionError, SCIONHeader.from_values, 'src',
                             dst)

    def test_bad_dst(self):
        src = MagicMock(spec_set=SCIONAddr)
        ntools.assert_raises(AssertionError, SCIONHeader.from_values, src,
                             'dst')

    def test_bad_path(self):
        src = MagicMock(spec_set=SCIONAddr)
        dst = MagicMock(spec_set=SCIONAddr)
        ntools.assert_raises(AssertionError, SCIONHeader.from_values, src,
                             dst, path='path')

    @patch("lib.packet.scion.SCIONHeader.set_ext_hdrs", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.set_path", autospec=True)
    @patch("lib.packet.scion.SCIONCommonHdr.from_values",
           spec_set=SCIONCommonHdr.from_values)
    def test_full(self, scion_common_hdr, set_path, set_ext_hdrs):
        src = MagicMock(spec_set=['addr_len', '__class__'])
        dst = MagicMock(spec_set=['addr_len', '__class__'])
        dst.__class__ = src.__class__ = SCIONAddr
        path = MagicMock(spec_set=PathBase)
        ext_hdrs = 'ext_hdrs'
        next_hdr = 100
        scion_common_hdr.return_value = 'scion_common_hdr'
        hdr = SCIONHeader.from_values(src, dst, path, ext_hdrs, next_hdr)
        ntools.assert_is_instance(hdr, SCIONHeader)
        scion_common_hdr.assert_called_once_with(src.addr_len, dst.addr_len,
                                                 next_hdr)
        ntools.eq_(hdr.common_hdr, 'scion_common_hdr')
        ntools.eq_(hdr.src_addr, src)
        ntools.eq_(hdr.dst_addr, dst)
        set_path.assert_called_once_with(hdr, path)
        set_ext_hdrs.assert_called_once_with(hdr, ext_hdrs)

    @patch("lib.packet.scion.SCIONHeader.set_ext_hdrs", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.set_path", autospec=True)
    @patch("lib.packet.scion.SCIONCommonHdr.from_values",
           spec_set=SCIONCommonHdr.from_values)
    def test_less_args(self, scion_common_hdr, set_path, set_ext_hdrs):
        src = MagicMock(spec_set=['addr_len', '__class__'])
        dst = MagicMock(spec_set=['addr_len', '__class__'])
        dst.__class__ = src.__class__ = SCIONAddr
        scion_common_hdr.return_value = 'scion_common_hdr'
        hdr = SCIONHeader.from_values(src, dst)
        scion_common_hdr.assert_called_once_with(src.addr_len, dst.addr_len, 0)
        set_path.assert_called_once_with(hdr, None)
        set_ext_hdrs.assert_called_once_with(hdr, [])


class TestSCIONHeaderPath(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.path
    """
    def test_getter(self):
        hdr = SCIONHeader()
        hdr._path = 'path'
        ntools.eq_(hdr.path, 'path')

    @patch("lib.packet.scion.SCIONHeader.set_path", autospec=True)
    def test_setter(self, set_path):
        hdr = SCIONHeader()
        hdr.path = 'path'
        set_path.assert_called_once_with(hdr, 'path')


class TestSCIONHeaderSetPath(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.set_path
    """
    @patch("lib.packet.scion.SCIONHeader.set_first_of_pointers", autospec=True)
    def test_with_none(self, set_first_of_pointers):
        hdr = SCIONHeader()
        hdr._path = MagicMock(spec_set=['pack'])
        hdr._path.pack.return_value = b'old_path'
        hdr.common_hdr = MagicMock(spec_set=['hdr_len', 'total_len'])
        hdr.common_hdr.hdr_len = 100
        hdr.common_hdr.total_len = 200
        hdr.set_path(None)
        ntools.eq_(hdr.common_hdr.hdr_len, 100 - len(b'old_path'))
        ntools.eq_(hdr.common_hdr.total_len, 200 - len(b'old_path'))
        ntools.assert_is_none(hdr._path)
        set_first_of_pointers.assert_called_once_with(hdr)

    @patch("lib.packet.scion.SCIONHeader.set_first_of_pointers", autospec=True)
    def test_not_none(self, set_first_of_pointers):
        hdr = SCIONHeader()
        hdr.common_hdr = MagicMock(spec_set=['hdr_len', 'total_len'])
        hdr.common_hdr.hdr_len = 100
        hdr.common_hdr.total_len = 200
        path = MagicMock(spec_set=['pack'])
        path.pack.return_value = b'packed_path'
        hdr.set_path(path)
        path.pack.assert_called_once_with()
        ntools.eq_(hdr._path, path)
        ntools.eq_(hdr.common_hdr.hdr_len, 100 + len(b'packed_path'))
        ntools.eq_(hdr.common_hdr.total_len, 200 + len(b'packed_path'))


class TestSCIONHeaderExtensionHdrs(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.extension_hdrs
    """
    def test_getter(self):
        hdr = SCIONHeader()
        hdr._extension_hdrs = 'ext_hdrs'
        ntools.eq_(hdr.extension_hdrs, 'ext_hdrs')

    @patch("lib.packet.scion.SCIONHeader.set_ext_hdrs", autospec=True)
    def test_setter(self, set_ext_hdrs):
        hdr = SCIONHeader()
        hdr.extension_hdrs = 'ext_hdrs'
        set_ext_hdrs.assert_called_once_with(hdr, 'ext_hdrs')


class TestSCIONHeaderSetExtHdrs(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.set_ext_hdrs
    """
    def test_bad_type(self):
        hdr = SCIONHeader()
        ntools.assert_raises(AssertionError, hdr.set_ext_hdrs, 123)

    @patch("lib.packet.scion.SCIONHeader.append_ext_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.pop_ext_hdr", autospec=True)
    def test_full(self, pop, append):
        hdr = SCIONHeader()
        ext_hdrs = ['ext_hdr0', 'ext_hdr1']
        hdr._extension_hdrs = MagicMock(spec_set=['__bool__'])
        hdr._extension_hdrs.__bool__.side_effect = [True, True, False]
        hdr.set_ext_hdrs(ext_hdrs)
        pop.assert_has_calls([call(hdr)] * 2)
        append.assert_has_calls([call(hdr, 'ext_hdr0'), call(hdr, 'ext_hdr1')])


class TestSCIONHeaderAppendExtHdr(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.append_ext_hdr
    """
    def test_bad_type(self):
        hdr = SCIONHeader()
        ntools.assert_raises(AssertionError, hdr.append_ext_hdr, 123)

    def test_full(self):
        hdr = SCIONHeader()
        hdr._extension_hdrs = []
        hdr.common_hdr = MagicMock(spec_set=['total_len'])
        hdr.common_hdr.total_len = 456
        ext_hdr = MagicMock(spec_set=ExtensionHeader)
        ext_hdr.__len__.return_value = 123
        hdr.append_ext_hdr(ext_hdr)
        ntools.assert_in(ext_hdr, hdr._extension_hdrs)
        ntools.eq_(hdr.common_hdr.total_len, 123 + 456)


class TestSCIONHeaderPopExtHdr(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.pop_ext_hdr
    """
    def test_none(self):
        hdr = SCIONHeader()
        hdr._extension_hdrs = []
        ntools.assert_is_none(hdr.pop_ext_hdr())

    def test_full(self):
        hdr = SCIONHeader()
        hdr._extension_hdrs = ['ext_hdr0', 'ext_hdr1']
        hdr.common_hdr = MagicMock(spec_set=['total_len'])
        hdr.common_hdr.total_len = 10
        ntools.eq_(hdr.pop_ext_hdr(), 'ext_hdr1')
        ntools.eq_(hdr._extension_hdrs, ['ext_hdr0'])
        ntools.eq_(hdr.common_hdr.total_len, 10 - len('ext_hdr1'))


class TestSCIONHeaderParse(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.parse
    """
    def test_bad_type(self):
        hdr = SCIONHeader()
        ntools.assert_raises(AssertionError, hdr.parse, 123)

    def test_bad_length(self):
        hdr = SCIONHeader()
        data = b'\x00' * (SCIONHeader.MIN_LEN - 1)
        hdr.parse(data)
        ntools.assert_false(hdr.parsed)

    @patch("lib.packet.scion.SCIONHeader._parse_extension_hdrs", autospec=True)
    @patch("lib.packet.scion.SCIONHeader._parse_opaque_fields", autospec=True)
    @patch("lib.packet.scion.SCIONHeader._parse_common_hdr", autospec=True)
    def test_full(self, parse_hdr, parse_ofs, parse_ext_hdrs):
        hdr = SCIONHeader()
        data = b'\x00' * SCIONHeader.MIN_LEN
        parse_hdr.return_value = 123
        parse_ofs.return_value = 456
        parse_ext_hdrs.return_value = 789
        ntools.eq_(hdr.parse(data), 789)
        parse_hdr.assert_called_once_with(hdr, data, 0)
        parse_ofs.assert_called_once_with(hdr, data, 123)
        parse_ext_hdrs.assert_called_once_with(hdr, data, 456)
        ntools.assert_true(hdr.parsed)


class TestSCIONHeaderParseCommonHdr(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader._parse_common_hdr
    """
    @patch("lib.packet.scion.SCIONCommonHdr", autospec=True)
    def test_fail(self, scion_common_hdr):
        hdr = SCIONHeader()
        common_hdr = MagicMock(spec_set=['parsed'])
        common_hdr.parsed = False
        scion_common_hdr.return_value = common_hdr
        ntools.assert_raises(AssertionError, hdr._parse_common_hdr, b'\x00' *
                             10, 0)

    @patch("lib.packet.scion.SCIONAddr", autospec=True)
    @patch("lib.packet.scion.SCIONCommonHdr", autospec=True)
    def test(self, scion_common_hdr, scion_addr):
        hdr = SCIONHeader()
        data = bytes(range(12))
        common_hdr = MagicMock(spec_set=['parsed', 'src_addr_len',
                                         'dst_addr_len'])
        common_hdr.parsed = True
        common_hdr.src_addr_len = 3
        common_hdr.dst_addr_len = 5
        scion_common_hdr.return_value = common_hdr
        scion_common_hdr.LEN = 2
        scion_addr.side_effect = ['src_addr', 'dst_addr']
        ntools.eq_(hdr._parse_common_hdr(data, 1), 1 + 2 + 3 + 5)
        scion_common_hdr.assert_called_once_with(data[1:3])
        ntools.eq_(hdr.common_hdr, common_hdr)
        scion_addr.assert_has_calls([call(data[3:6]), call(data[6:11])])
        ntools.eq_(hdr.src_addr, 'src_addr')
        ntools.eq_(hdr.dst_addr, 'dst_addr')


class TestSCIONHeaderParseOpaqueFields(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader._parse_opaque_fields
    """
    @patch("lib.packet.scion.EmptyPath", autospec=True)
    def test_empty_path(self, empty_path):
        hdr = SCIONHeader()
        hdr.common_hdr = MagicMock(spec_set=['hdr_len'])
        hdr.common_hdr.hdr_len = 123
        empty_path.return_value = 'empty_path'
        ntools.eq_(hdr._parse_opaque_fields(b'\x00' * 10, 123), 123)
        empty_path.assert_called_once_with()
        ntools.eq_(hdr._path, 'empty_path')

    @patch("lib.packet.scion.PeerPath", autospec=True)
    @patch("lib.packet.scion.CrossOverPath", autospec=True)
    @patch("lib.packet.scion.CorePath", autospec=True)
    @patch("lib.packet.scion.InfoOpaqueField", autospec=True)
    def _check(self, oft, path, iof, core_path, cross_over_path, peer_path):
        hdr = SCIONHeader()
        info = MagicMock(spec_set=['info'])
        info.info = oft
        iof.return_value = info
        core_path.return_value = 'core_path'
        cross_over_path.return_value = 'cross_over_path'
        peer_path.return_value = 'peer_path'
        common_hdr = MagicMock(spec_set=['hdr_len'])
        common_hdr.hdr_len = 3
        hdr.common_hdr = common_hdr
        data = bytes(range(10))
        ntools.eq_(hdr._parse_opaque_fields(data, 0), 3)
        ntools.eq_(hdr._path, path)

    def test_other_paths(self):
        ofts = [OFT.TDC_XOVR, OFT.NON_TDC_XOVR, OFT.INTRATD_PEER,
                OFT.INTERTD_PEER, 123]
        paths = ['core_path', 'cross_over_path', 'peer_path', 'peer_path', None]
        for oft, path in zip(ofts, paths):
            yield self._check, oft, path


class TestSCIONHeaderParseExtensionHdrs(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader._parse_extension_hdrs
    """
    @patch("lib.packet.scion.ExtensionHeader", autospec=True)
    @patch("lib.packet.scion.ICNExtHdr", autospec=True)
    def test(self, icn_ext_hdr, ext_hdr):
        hdr = SCIONHeader()
        hdr._extension_hdrs = ['old_ext_hdr']
        hdr.common_hdr = MagicMock(spec_set=['next_hdr'])
        hdr.common_hdr.next_hdr = 1
        icn_ext_hdr.TYPE = 1
        icn_ext_hdr.return_value = 'icn_ext_hdr'
        ext_hdr.return_value = 'ext_hdr'
        data = bytes.fromhex('00 02 03 12 00 02 34')
        ntools.eq_(hdr._parse_extension_hdrs(data, 1), 1 + 3 + 2)
        icn_ext_hdr.assert_called_once_with(data[1:4])
        ext_hdr.assert_called_once_with(data[4:6])
        ntools.eq_(hdr._extension_hdrs, ['old_ext_hdr', 'icn_ext_hdr',
                                         'ext_hdr'])


class TestSCIONHeaderPack(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.pack
    """
    def _check(self, path, packed_path):
        hdr = SCIONHeader()
        hdr.common_hdr = MagicMock(spec_set=['pack'])
        hdr.common_hdr.pack.return_value = b'common_hdr'
        hdr.src_addr = MagicMock(spec_set=['pack'])
        hdr.src_addr.pack.return_value = b'src_addr'
        hdr.dst_addr = MagicMock(spec_set=['pack'])
        hdr.dst_addr.pack.return_value = b'dst_addr'
        hdr._path = path
        hdr._extension_hdrs = [MagicMock(spec_set=['pack']) for i in range(2)]
        for i, ext_hdr in enumerate(hdr._extension_hdrs):
            ext_hdr.pack.return_value = b'ext_hdr' + str.encode(str(i))
        packed = b'common_hdrsrc_addrdst_addr' + packed_path + \
                 b'ext_hdr0ext_hdr1'
        ntools.eq_(hdr.pack(), packed)

    def test(self):
        paths = [None, MagicMock(spec_set=['pack'])]
        paths[1].pack.return_value = b'path'
        packed_paths = [b'', b'path']
        for path, packed_path in zip(paths, packed_paths):
            yield self._check, path, packed_path


class TestSCIONHeaderGetCurrentOf(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.get_current_of
    """
    def test_none(self):
        hdr = SCIONHeader()
        ntools.assert_is_none(hdr.get_current_of())

    def test(self):
        hdr = SCIONHeader()
        hdr.common_hdr = MagicMock(spec_set=['curr_of_p', 'src_addr_len',
                                             'dst_addr_len'])
        hdr.common_hdr.curr_of_p = 123
        hdr.common_hdr.src_addr_len = 456
        hdr.common_hdr.dst_addr_len = 789
        hdr._path = MagicMock(spec_set=['get_of'])
        hdr._path.get_of.return_value = 'get_current_of'
        offset = 123 - (456 + 789)
        ntools.eq_(hdr.get_current_of(), 'get_current_of')
        hdr._path.get_of.assert_called_once_with(offset // OpaqueField.LEN)


class TestSCIONHeaderGetCurrentIof(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.get_current_iof
    """
    def test_none(self):
        hdr = SCIONHeader()
        ntools.assert_is_none(hdr.get_current_iof())

    def test(self):
        hdr = SCIONHeader()
        hdr.common_hdr = MagicMock(spec_set=['curr_iof_p', 'src_addr_len',
                                             'dst_addr_len'])
        hdr.common_hdr.curr_iof_p = 123
        hdr.common_hdr.src_addr_len = 456
        hdr.common_hdr.dst_addr_len = 789
        hdr._path = MagicMock(spec_set=['get_of'])
        hdr._path.get_of.return_value = 'get_current_iof'
        offset = 123 - (456 + 789)
        ntools.eq_(hdr.get_current_iof(), 'get_current_iof')
        hdr._path.get_of.assert_called_once_with(offset // OpaqueField.LEN)


class TestSCIONHeaderGetRelativeOf(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.get_relative_of
    """
    def test_none(self):
        hdr = SCIONHeader()
        ntools.assert_is_none(hdr.get_relative_of(123))

    def test(self):
        hdr = SCIONHeader()
        hdr.common_hdr = MagicMock(spec_set=['curr_of_p', 'src_addr_len',
                                             'dst_addr_len'])
        hdr.common_hdr.curr_of_p = 123
        hdr.common_hdr.src_addr_len = 456
        hdr.common_hdr.dst_addr_len = 789
        hdr._path = MagicMock(spec_set=['get_of'])
        hdr._path.get_of.return_value = 'get_relative_of'
        offset = 123 - (456 + 789)
        ntools.eq_(hdr.get_relative_of(321), 'get_relative_of')
        hdr._path.get_of.assert_called_once_with(offset // OpaqueField.LEN +
                                                 321)


class TestSCIONHeaderGetNextOf(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.get_next_of
    """
    def test_none(self):
        hdr = SCIONHeader()
        ntools.assert_is_none(hdr.get_next_of())

    def test(self):
        hdr = SCIONHeader()
        hdr.common_hdr = MagicMock(spec_set=['curr_of_p', 'src_addr_len',
                                             'dst_addr_len'])
        hdr.common_hdr.curr_of_p = 123
        hdr.common_hdr.src_addr_len = 456
        hdr.common_hdr.dst_addr_len = 789
        hdr._path = MagicMock(spec_set=['get_of'])
        hdr._path.get_of.return_value = 'get_next_of'
        offset = 123 - (456 + 789)
        ntools.eq_(hdr.get_next_of(), 'get_next_of')
        hdr._path.get_of.assert_called_once_with(offset // OpaqueField.LEN + 1)


class TestSCIONHeaderIncreaseOf(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.increase_of
    """
    def test(self):
        hdr = SCIONHeader()
        hdr.common_hdr = MagicMock(spec_set=['curr_of_p'])
        hdr.common_hdr.curr_of_p = 456
        hdr.increase_of(123)
        ntools.eq_(hdr.common_hdr.curr_of_p, 456 + 123 * OpaqueField.LEN)


class TestSCIONHeaderSetDownpath(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.set_downpath
    """
    @patch("lib.packet.scion.SCIONHeader.get_current_iof", autospec=True)
    def test_iof_none(self, get_current_iof):
        hdr = SCIONHeader()
        get_current_iof.return_value = None
        hdr.set_downpath()
        get_current_iof.assert_called_once_with(hdr)

    @patch("lib.packet.scion.SCIONHeader.get_current_iof", autospec=True)
    def test_with_iof(self, get_current_iof):
        hdr = SCIONHeader()
        iof = MagicMock(spec_set=['up_flag'])
        get_current_iof.return_value = iof
        hdr.set_downpath()
        ntools.assert_false(iof.up_flag)


class TestSCIONHeaderIsOnUpPath(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.is_on_up_path
    """
    @patch("lib.packet.scion.SCIONHeader.get_current_iof", autospec=True)
    def test_iof_none(self, get_current_iof):
        hdr = SCIONHeader()
        get_current_iof.return_value = None
        ntools.assert_true(hdr.is_on_up_path())
        get_current_iof.assert_called_once_with(hdr)

    @patch("lib.packet.scion.SCIONHeader.get_current_iof", autospec=True)
    def test_with_iof(self, get_current_iof):
        hdr = SCIONHeader()
        iof = MagicMock(spec_set=['up_flag'])
        get_current_iof.return_value = iof
        ntools.eq_(hdr.is_on_up_path(), iof.up_flag)


class TestSCIONHeaderIsLastPathOf(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.is_last_path_of
    """
    def test_true(self):
        hdr = SCIONHeader()
        offset = (SCIONCommonHdr.LEN + OpaqueField.LEN)
        hdr.common_hdr = MagicMock(spec_set=['curr_of_p', 'hdr_len'])
        hdr.common_hdr.curr_of_p = 123
        hdr.common_hdr.hdr_len = 123 + offset
        ntools.assert_true(hdr.is_last_path_of())

    def test_false(self):
        hdr = SCIONHeader()
        offset = (SCIONCommonHdr.LEN + OpaqueField.LEN)
        hdr.common_hdr = MagicMock(spec_set=['curr_of_p', 'hdr_len'])
        hdr.common_hdr.curr_of_p = 123
        hdr.common_hdr.hdr_len = 456 + offset
        ntools.assert_false(hdr.is_last_path_of())


class TestSCIONHeaderReverse(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.reverse
    """
    @patch("lib.packet.scion.SCIONHeader.set_first_of_pointers", autospec=True)
    def test(self, set_first_of_pointers):
        hdr = SCIONHeader()
        hdr.src_addr = 'src_addr'
        hdr.dst_addr = 'dst_addr'
        hdr._path = MagicMock(spec_set=['reverse'])
        hdr.reverse()
        ntools.eq_(hdr.src_addr, 'dst_addr')
        ntools.eq_(hdr.dst_addr, 'src_addr')
        hdr._path.reverse.assert_called_once_with()
        set_first_of_pointers.assert_called_once_with(hdr)


class TestSCIONHeaderSetFirstOfPointers(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.set_first_of_pointers
    """
    def test_without_path(self):
        hdr = SCIONHeader()
        common_hdr = MagicMock(spec_set=['curr_iof_p', 'src_addr_len',
                                         'dst_addr_len', 'curr_of_p'])
        common_hdr.curr_of_p = 123
        common_hdr.curr_iof_p = 456
        hdr.common_hdr = common_hdr
        hdr.set_first_of_pointers()
        ntools.eq_(hdr.common_hdr.curr_of_p, 123)
        ntools.eq_(hdr.common_hdr.curr_iof_p, 456)

    def test_with_path(self):
        hdr = SCIONHeader()
        common_hdr = MagicMock(spec_set=['curr_iof_p', 'src_addr_len',
                                         'dst_addr_len', 'curr_of_p'])
        common_hdr.src_addr_len = 12
        common_hdr.dst_addr_len = 34
        hdr.common_hdr = common_hdr
        path = MagicMock(spec_set=['get_first_hop_offset',
                                   'get_first_info_offset'])
        path.get_first_hop_offset.return_value = 56
        path.get_first_info_offset.return_value = 78
        hdr._path = path
        hdr.set_first_of_pointers()
        path.get_first_hop_offset.assert_called_once_with()
        path.get_first_info_offset.assert_called_once_with()
        ntools.eq_(hdr.common_hdr.curr_of_p, 12 + 34 + 56)
        ntools.eq_(hdr.common_hdr.curr_iof_p, 12 + 34 + 78)


class TestSCIONHeaderLen(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.__len__
    """
    def test(self):
        hdr = SCIONHeader()
        hdr.common_hdr = MagicMock(spec_set=['hdr_len'])
        hdr.common_hdr.hdr_len = 123
        hdr._extension_hdrs = ['ext_hdr0', 'ext_hdr01']
        ntools.eq_(len(hdr), 123 + len('ext_hdr0') + len('ext_hdr01'))


class TestSCIONPacketInit(object):
    """
    Unit tests for lib.packet.scion.SCIONPacket.__init__
    """
    @patch("lib.packet.scion.PacketBase.__init__", autospec=True)
    def test_basic(self, init):
        packet = SCIONPacket()
        init.assert_called_once_with(packet)
        ntools.eq_(packet.payload_len, 0)

    @patch("lib.packet.scion.SCIONPacket.parse", autospec=True)
    def test_with_args(self, parse):
        packet = SCIONPacket('data')
        parse.assert_called_once_with(packet, 'data')


class TestSCIONPacketFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONPacket.from_values
    """
    @patch("lib.packet.scion.SCIONPacket.set_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    def test_basic(self, scion_hdr, set_payload, set_hdr):
        scion_hdr.return_value = 'hdr'
        packet = SCIONPacket.from_values('src', 'dst', 'payload', 'path',
                                         'ext_hdrs', 'next_hdr')
        ntools.assert_is_instance(packet, SCIONPacket)
        scion_hdr.assert_called_once_with('src', 'dst', 'path', 'ext_hdrs',
                                          'next_hdr')
        set_hdr.assert_called_once_with(packet, 'hdr')
        set_payload.assert_called_once_with(packet, 'payload')

    @patch("lib.packet.scion.SCIONPacket.set_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    def test_less_args(self, scion_hdr, set_payload, set_hdr):
        SCIONPacket.from_values('src', 'dst', 'payload')
        scion_hdr.assert_called_once_with('src', 'dst', None, None, 0)


class TestSCIONPacketSetPayload(object):
    """
    Unit tests for lib.packet.scion.SCIONPacket.set_payload
    """
    @patch("lib.packet.scion.PacketBase.set_payload", autospec=True)
    def test(self, set_payload):
        packet = SCIONPacket()
        packet.payload_len = 123
        packet._hdr = MagicMock(spec_set=['common_hdr'])
        packet._hdr.common_hdr = MagicMock(spec_set=['total_len'])
        packet._hdr.common_hdr.total_len = 456
        packet.set_payload('payload')
        set_payload.assert_called_once_with(packet, 'payload')
        ntools.eq_(packet.payload_len, len('payload'))
        ntools.eq_(packet.hdr.common_hdr.total_len, 456 - 123 + len('payload'))


class TestSCIONPacketParse(object):
    """
    Unit tests for lib.packet.scion.SCIONPacket.parse
    """
    def test_bad_type(self):
        packet = SCIONPacket()
        ntools.assert_raises(AssertionError, packet.parse, 123)

    def test_bad_length(self):
        packet = SCIONPacket()
        data = b'\x00' * (SCIONPacket.MIN_LEN - 1)
        packet.parse(data)
        ntools.assert_false(packet.parsed)

    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONPacket.set_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONHeader", autospec=True)
    def test_full(self, scion_hdr, set_hdr, set_payload):
        packet = SCIONPacket()
        packet._hdr = 'header'
        data = bytes(range(SCIONPacket.MIN_LEN))
        scion_hdr.return_value = 'scion_header'
        packet.parse(data)
        ntools.eq_(packet.raw, data)
        scion_hdr.assert_called_once_with(data)
        set_hdr.assert_called_once_with(packet, 'scion_header')
        hdr_len = len(packet.hdr)
        ntools.eq_(packet.payload_len, len(data) - hdr_len)
        set_payload.assert_called_once_with(packet, data[hdr_len:])
        ntools.assert_true(packet.parsed)


class TestSCIONPacketPack(object):
    """
    Unit tests for lib.packet.scion.SCIONPacket.pack
    """
    def test_payload_packetbase(self):
        packet = SCIONPacket()
        packet._hdr = MagicMock(spec_set=['pack'])
        packet._hdr.pack.return_value = b'packed_hdr'
        packet._payload = MagicMock(spec_set=SCIONPacket)
        packet._payload.pack.return_value = b'packed_payload'
        ntools.eq_(packet.pack(), b'packed_hdrpacked_payload')

    def test_payload_bytes(self):
        packet = SCIONPacket()
        packet._hdr = MagicMock(spec_set=['pack'])
        packet._hdr.pack.return_value = b'packed_hdr'
        packet._payload = b'packed_payload'
        ntools.eq_(packet.pack(), b'packed_hdrpacked_payload')


class TestIFIDPacketInit(object):
    """
    Unit tests for lib.packet.scion.IFIDPacket.__init__
    """
    @patch("lib.packet.scion.SCIONPacket.__init__", autospec=True)
    def test_basic(self, init):
        packet = IFIDPacket()
        init.assert_called_once_with(packet)
        ntools.eq_(packet.reply_id, 0)
        ntools.assert_is_none(packet.request_id)

    @patch("lib.packet.scion.IFIDPacket.parse", autospec=True)
    def test_with_args(self, parse):
        packet = IFIDPacket('data')
        parse.assert_called_once_with(packet, 'data')


class TestIFIDPacketParse(object):
    """
    Unit tests for lib.packet.scion.IFIDPacket.parse
    """
    @patch("lib.packet.scion.SCIONPacket.parse", autospec=True)
    def test(self, parse):
        packet = IFIDPacket()
        packet._payload = bytes.fromhex('0102 0304')
        packet.parse('data')
        parse.assert_called_once_with(packet, 'data')
        ntools.eq_(packet.reply_id, 0x0102)
        ntools.eq_(packet.request_id, 0x0304)


class TestIFIDPacketFromValues(object):
    """
    Unit tests for lib.packet.scion.IFIDPacket.from_values
    """
    @patch("lib.packet.scion.IFIDPacket.set_payload", autospec=True)
    @patch("lib.packet.scion.IFIDPacket.set_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    @patch("lib.packet.scion.SCIONAddr.from_values",
           spec_set=SCIONAddr.from_values)
    def test(self, scion_addr, scion_hdr, set_hdr, set_payload):
        scion_addr.return_value = 'dst'
        dst_isd_ad = MagicMock(spec_set=['isd', 'ad'])
        scion_hdr.return_value = 'hdr'
        packet = IFIDPacket.from_values('src', dst_isd_ad, 0x0102)
        ntools.assert_is_instance(packet, IFIDPacket)
        ntools.eq_(packet.request_id, 0x0102)
        scion_addr.assert_called_once_with(dst_isd_ad.isd, dst_isd_ad.ad,
                                           PacketType.IFID_PKT)
        scion_hdr.assert_called_once_with('src', 'dst')
        set_hdr.assert_called_once_with(packet, 'hdr')
        set_payload.assert_called_once_with(packet, bytes.fromhex('0000 0102'))


class TestIFIDPacketPack(object):
    """
    Unit tests for lib.packet.scion.IFIDPacket.pack
    """
    @patch("lib.packet.scion.SCIONPacket.pack", autospec=True)
    @patch("lib.packet.scion.IFIDPacket.set_payload", autospec=True)
    def test(self, set_payload, pack):
        packet = IFIDPacket()
        packet.reply_id = 0x0102
        packet.request_id = 0x0304
        pack.return_value = b'packed_ifid'
        ntools.eq_(packet.pack(), b'packed_ifid')
        set_payload.assert_called_once_with(packet, bytes.fromhex('0102 0304'))
        pack.assert_called_once_with(packet)


class TestCertChainRequestInit(object):
    """
    Unit tests for lib.packet.scion.CertChainRequest.__init__
    """
    @patch("lib.packet.scion.SCIONPacket.__init__", autospec=True)
    def test_basic(self, init):
        req = CertChainRequest()
        init.assert_called_once_with(req)
        ntools.eq_(req.ingress_if, 0)
        ntools.eq_(req.src_isd, 0)
        ntools.eq_(req.src_ad, 0)
        ntools.eq_(req.isd_id, 0)
        ntools.eq_(req.ad_id, 0)
        ntools.eq_(req.version, 0)

    @patch("lib.packet.scion.CertChainRequest.parse", autospec=True)
    def test_with_args(self, parse):
        req = CertChainRequest('data')
        parse.assert_called_once_with(req, 'data')


class TestCertChainRequestParse(object):
    """
    Unit tests for lib.packet.scion.CertChainRequest.parse
    """
    @patch("lib.packet.scion.ISD_AD.from_raw", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.scion.SCIONPacket.parse", autospec=True)
    def test(self, parse, isd_ad):
        req = CertChainRequest()
        raw = req._payload = bytes.fromhex('0102 0bc0021d 021004c6 1718191a')
        isd_ad.side_effect = [(0x0bc, 0x0021d), (0x021, 0x004c6)]
        req.parse('data')
        parse.assert_called_once_with(req, 'data')
        ntools.eq_(req.ingress_if, 0x0102)
        ntools.eq_(req.src_isd, 0x0bc)
        ntools.eq_(req.src_ad, 0x0021d)
        ntools.eq_(req.isd_id, 0x021)
        ntools.eq_(req.ad_id, 0x004c6)
        isd_ad.assert_has_calls([call(raw[2:2 + ISD_AD.LEN]),
                                 call(raw[2 + ISD_AD.LEN:2 + 2 * ISD_AD.LEN])])
        ntools.eq_(req.version, 0x1718191a)


class TestCertChainRequestFromValues(object):
    """
    Unit tests for lib.packet.scion.CertChainRequest.from_values
    """
    @patch("lib.packet.scion.ISD_AD", autospec=True)
    @patch("lib.packet.scion.CertChainRequest.set_payload", autospec=True)
    @patch("lib.packet.scion.CertChainRequest.set_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    @patch("lib.packet.scion.SCIONAddr.from_values",
           spec_set=SCIONAddr.from_values)
    def test(self, scion_addr, scion_hdr, set_hdr, set_payload, isd_ad):
        scion_addr.return_value = 'dst'
        scion_hdr.return_value = 'hdr'
        (ingress_if, src_isd, src_ad, isd_id, ad_id, version) = \
            (0x0102, 0x001, 0x60010, 0x00d, 0x003d9, 0x0b0c)
        isd_ads = [MagicMock(spec_set=['pack']), MagicMock(spec_set=['pack'])]
        isd_ads[0].pack.return_value = bytes.fromhex('00160010')
        isd_ads[1].pack.return_value = bytes.fromhex('00d003d9')
        isd_ad.side_effect = isd_ads
        req = CertChainRequest.from_values('req_type', 'src', ingress_if,
                                           src_isd, src_ad, isd_id, ad_id,
                                           version)
        ntools.assert_is_instance(req, CertChainRequest)
        scion_addr.assert_called_once_with(isd_id, src_ad, 'req_type')
        scion_hdr.assert_called_once_with('src', 'dst')
        set_hdr.assert_called_once_with(req, 'hdr')
        ntools.eq_(req.ingress_if, ingress_if)
        ntools.eq_(req.src_isd, src_isd)
        ntools.eq_(req.src_ad, src_ad)
        ntools.eq_(req.isd_id, isd_id)
        ntools.eq_(req.ad_id, ad_id)
        ntools.eq_(req.version, version)
        isd_ad.assert_has_calls([call(src_isd, src_ad), call(isd_id, ad_id)])
        isd_ads[0].pack.assert_called_once_with()
        isd_ads[1].pack.assert_called_once_with()
        payload = bytes.fromhex('0102 00160010 00d003d9 00000b0c')
        set_payload.assert_called_once_with(req, payload)


class TestCertChainReplyInit(object):
    """
    Unit tests for lib.packet.scion.CertChainReply.__init__
    """
    @patch("lib.packet.scion.SCIONPacket.__init__", autospec=True)
    def test_basic(self, init):
        rep = CertChainReply()
        init.assert_called_once_with(rep)
        ntools.eq_(rep.isd_id, 0)
        ntools.eq_(rep.ad_id, 0)
        ntools.eq_(rep.version, 0)
        ntools.eq_(rep.cert_chain, b'')

    @patch("lib.packet.scion.CertChainReply.parse", autospec=True)
    def test_with_args(self, parse):
        rep = CertChainReply('data')
        parse.assert_called_once_with(rep, 'data')


class TestCertChainReplyParse(object):
    """
    Unit tests for lib.packet.scion.CertChainReply.parse
    """
    @patch("lib.packet.scion.ISD_AD.from_raw", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.scion.SCIONPacket.parse", autospec=True)
    def test(self, parse, isd_ad):
        rep = CertChainReply()
        raw = rep._payload = bytes.fromhex('0bc0021d 1718191a') + b'\x00' * 10
        isd_ad.return_value = (0x0bc, 0x0021d)
        rep.parse('data')
        parse.assert_called_once_with(rep, 'data')
        isd_ad.assert_called_once_with(raw[:ISD_AD.LEN])
        ntools.eq_(rep.isd_id, 0x0bc)
        ntools.eq_(rep.ad_id, 0x0021d)
        ntools.eq_(rep.version, 0x1718191a)
        ntools.eq_(rep.cert_chain, b'\x00' * 10)


class TestCertChainReplyFromValues(object):
    """
    Unit tests for lib.packet.scion.CertChainReply.from_values
    """
    @patch("lib.packet.scion.ISD_AD", autospec=True)
    @patch("lib.packet.scion.CertChainReply.set_payload", autospec=True)
    @patch("lib.packet.scion.CertChainReply.set_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    @patch("lib.packet.scion.SCIONAddr.from_values",
           spec_set=SCIONAddr.from_values)
    def test(self, scion_addr, scion_hdr, set_hdr, set_payload, isd_ad):
        scion_addr.return_value = 'src'
        scion_hdr.return_value = 'hdr'
        (isd_id, ad_id, version) = (0x0bc, 0x0021d, 0x0506)
        isd_ad_mock = isd_ad.return_value = MagicMock(spec_set=['pack'])
        isd_ad_mock.pack.return_value = bytes.fromhex('0bc0021d')
        rep = CertChainReply.from_values('dst', isd_id, ad_id, version,
                                         b'cert_chain')
        ntools.assert_is_instance(rep, CertChainReply)
        scion_addr.assert_called_once_with(isd_id, ad_id,
                                           PacketType.CERT_CHAIN_REP)
        scion_hdr.assert_called_once_with('src', 'dst')
        set_hdr.assert_called_once_with(rep, 'hdr')
        ntools.eq_(rep.isd_id, isd_id)
        ntools.eq_(rep.ad_id, ad_id)
        ntools.eq_(rep.version, version)
        ntools.eq_(rep.cert_chain, b'cert_chain')
        isd_ad.assert_called_once_with(isd_id, ad_id)
        isd_ad_mock.pack.assert_called_once_with()
        payload = bytes.fromhex('0bc0021d 00000506') + \
            b'cert_chain'
        set_payload.assert_called_once_with(rep, payload)


class TestTRCRequestInit(object):
    """
    Unit tests for lib.packet.scion.TRCRequest.__init__
    """
    @patch("lib.packet.scion.SCIONPacket.__init__", autospec=True)
    def test_basic(self, init):
        req = TRCRequest()
        init.assert_called_once_with(req)
        ntools.eq_(req.ingress_if, 0)
        ntools.eq_(req.src_isd, 0)
        ntools.eq_(req.src_ad, 0)
        ntools.eq_(req.isd_id, 0)
        ntools.eq_(req.version, 0)

    @patch("lib.packet.scion.TRCRequest.parse", autospec=True)
    def test_with_args(self, parse):
        req = TRCRequest('data')
        parse.assert_called_once_with(req, 'data')


class TestTRCRequestParse(object):
    """
    Unit tests for lib.packet.scion.TRCRequest.parse
    """
    @patch("lib.packet.scion.ISD_AD.from_raw", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.scion.SCIONPacket.parse", autospec=True)
    def test(self, parse, isd_ad):
        req = TRCRequest()
        raw = req._payload = bytes.fromhex('0102 00160010 0708 0000090a')
        isd_ad.return_value = (0x001, 0x60010)
        req.parse('data')
        parse.assert_called_once_with(req, 'data')
        ntools.eq_(req.ingress_if, 0x0102)
        isd_ad.assert_called_once_with(raw[2:2 + ISD_AD.LEN])
        ntools.eq_(req.src_isd, 0x001)
        ntools.eq_(req.src_ad, 0x60010)
        ntools.eq_(req.isd_id, 0x0708)
        ntools.eq_(req.version, 0x0000090a)


class TestTRCRequestFromValues(object):
    """
    Unit tests for lib.packet.scion.TRCRequest.from_values
    """
    @patch("lib.packet.scion.ISD_AD", autospec=True)
    @patch("lib.packet.scion.TRCRequest.set_payload", autospec=True)
    @patch("lib.packet.scion.TRCRequest.set_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    @patch("lib.packet.scion.SCIONAddr.from_values",
           spec_set=SCIONAddr.from_values)
    def test(self, scion_addr, scion_hdr, set_hdr, set_payload, isd_ad):
        scion_addr.return_value = 'dst'
        scion_hdr.return_value = 'hdr'
        (ingress_if, src_isd, src_ad, isd_id, version) = \
            (0x0102, 0x001, 0x60010, 0x0708, 0x090a)
        isd_ad_mock = isd_ad.return_value = MagicMock(spec_set=['pack'])
        isd_ad_mock.pack.return_value = bytes.fromhex('00160010')
        req = TRCRequest.from_values('req_type', 'src', ingress_if, src_isd,
                                     src_ad, isd_id, version)
        ntools.assert_is_instance(req, TRCRequest)
        scion_addr.assert_called_once_with(isd_id, src_ad, 'req_type')
        scion_hdr.assert_called_once_with('src', 'dst')
        set_hdr.assert_called_once_with(req, 'hdr')
        ntools.eq_(req.ingress_if, ingress_if)
        ntools.eq_(req.src_isd, src_isd)
        ntools.eq_(req.src_ad, src_ad)
        ntools.eq_(req.isd_id, isd_id)
        ntools.eq_(req.version, version)
        isd_ad.assert_called_once_with(src_isd, src_ad)
        isd_ad_mock.pack.assert_called_once_with()
        payload = bytes.fromhex('0102 00160010 0708 0000090a')
        set_payload.assert_called_once_with(req, payload)


class TestTRCReplyInit(object):
    """
    Unit tests for lib.packet.scion.TRCReply.__init__
    """
    @patch("lib.packet.scion.SCIONPacket.__init__", autospec=True)
    def test_basic(self, init):
        rep = TRCReply()
        init.assert_called_once_with(rep)
        ntools.eq_(rep.isd_id, 0)
        ntools.eq_(rep.version, 0)
        ntools.eq_(rep.trc, b'')

    @patch("lib.packet.scion.TRCReply.parse", autospec=True)
    def test_with_args(self, parse):
        rep = TRCReply('data')
        parse.assert_called_once_with(rep, 'data')


class TestTRCReplyParse(object):
    """
    Unit tests for lib.packet.scion.TRCReply.parse
    """
    @patch("lib.packet.scion.SCIONPacket.parse", autospec=True)
    def test(self, parse):
        rep = TRCReply()
        rep._payload = bytes.fromhex('0102 03040506') + b'\x00' * 10
        rep.parse('data')
        parse.assert_called_once_with(rep, 'data')
        ntools.eq_(rep.isd_id, 0x0102)
        ntools.eq_(rep.version, 0x03040506)
        ntools.eq_(rep.trc, b'\x00' * 10)


class TestTRCReplyFromValues(object):
    """
    Unit tests for lib.packet.scion.TRCReply.from_values
    """
    @patch("lib.packet.scion.TRCReply.set_payload", autospec=True)
    @patch("lib.packet.scion.TRCReply.set_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    @patch("lib.packet.scion.SCIONAddr.from_values",
           spec_set=SCIONAddr.from_values)
    def test(self, scion_addr, scion_hdr, set_hdr, set_payload):
        scion_addr.return_value = 'src'
        scion_hdr.return_value = 'hdr'
        (isd_id, version) = (0x0102, 0x03040506)
        dst = MagicMock(spec_set=['isd_id', 'ad_id'])
        rep = TRCReply.from_values(dst, isd_id, version, b'trc')
        ntools.assert_is_instance(rep, TRCReply)
        scion_addr.assert_called_once_with(dst.isd_id, dst.ad_id,
                                           PacketType.TRC_REP)
        scion_hdr.assert_called_once_with('src', dst)
        set_hdr.assert_called_once_with(rep, 'hdr')
        ntools.eq_(rep.isd_id, isd_id)
        ntools.eq_(rep.version, version)
        ntools.eq_(rep.trc, b'trc')
        payload = bytes.fromhex('0102 03040506') + b'trc'
        set_payload.assert_called_once_with(rep, payload)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
