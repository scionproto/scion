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
:mod:`lib_packet_scion_test` --- lib.packet.scion unit tests
============================================================
"""
# Stdlib
from unittest.mock import patch, MagicMock, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.path import PathBase
from lib.packet.scion import (
    get_type,
    SCIONCommonHdr, SCIONHeader)
from lib.packet.scion_addr import SCIONAddr


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
        data = bytes.fromhex('a102 0304 05 06 07 08')
        hdr.parse(data)
        ntools.eq_(hdr.total_len, 0x0304)
        ntools.eq_(hdr.curr_iof_p, 0x05)
        ntools.eq_(hdr.curr_of_p, 0x06)
        ntools.eq_(hdr.next_hdr, 0x07)
        ntools.eq_(hdr.hdr_len, 0x08)
        types = 0xa102
        ntools.eq_(hdr.version, (types & 0xf000) >> 12)
        ntools.eq_(hdr.src_addr_len, (types & 0x0fc0) >> 6)
        ntools.eq_(hdr.dst_addr_len, types & 0x003f)
        ntools.assert_true(hdr.parsed)


class TestSCIONCommonHdrPack(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.pack
    """
    def test(self):
        hdr = SCIONCommonHdr()
        hdr.version = 0xa
        hdr.dst_addr_len = 0x2
        hdr.src_addr_len = 0x4
        hdr.total_len = 0x304
        hdr.curr_iof_p = 0x5
        hdr.curr_of_p = 0x6
        hdr.next_hdr = 0x7
        hdr.hdr_len = 0x8
        packed = bytes.fromhex('a102 0304 05 06 07 08')
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
    def test_with_none(self):
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

    def test_not_none(self):
        hdr = SCIONHeader()
        hdr._path = MagicMock(spec_set=['pack'])
        hdr._path.pack.return_value = b'old_path'
        hdr.common_hdr = MagicMock(spec_set=['hdr_len', 'total_len'])
        hdr.common_hdr.hdr_len = 100
        hdr.common_hdr.total_len = 200
        path = MagicMock(spec_set=['pack'])
        path.pack.return_value = b'packed_path'
        hdr.set_path(path)
        ntools.eq_(hdr._path, path)
        ntools.eq_(hdr.common_hdr.hdr_len,
                   100 - len(b'old_path') + len(b'packed_path'))
        ntools.eq_(hdr.common_hdr.total_len,
                   200 - len(b'old_path') + len(b'packed_path'))


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
    Unit tests for lib.packet.scion.SCIONHeader.set_path
    """
    def test_bad_type(self):
        hdr = SCIONHeader()
        ntools.assert_raises(AssertionError, hdr.set_ext_hdrs, 123)

    @patch("lib.packet.scion.SCIONHeader.append_ext_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.pop_ext_hdr", autospec=True)
    def test_full(self, pop, append):
        hdr = SCIONHeader()
        ext_hdrs = ['ext_hdr0', 'ext_hdr1']
        # hdr._extension_hdrs = ['old_ext_hdr' + str(i) for i in range(3)]
        # FIXME: pop_ext_hdr side effect should 'pop' hdr._extension_hdrs
        hdr.set_ext_hdrs(ext_hdrs)
        # pop.assert_has_calls([call()] * 3)
        append.assert_has_calls([call(hdr, 'ext_hdr0'), call(hdr, 'ext_hdr1')])


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
