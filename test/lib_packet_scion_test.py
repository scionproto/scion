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
from lib.defines import L4_DEFAULT, L4_RESERVED, L4_UDP
from lib.packet.opaque_field import (
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
from test.testcommon import assert_these_calls, create_mock


class TestGetType(object):
    """
    Unit tests for lib.packet.scion.get_type
    """
    @patch("lib.packet.scion.PacketType", autospec=True)
    def test_in_src(self, packet_type):
        pkt = create_mock(['hdr'])
        pkt.hdr = create_mock(['src_addr'])
        pkt.hdr.src_addr = create_mock(['host_addr'])
        pkt.hdr.src_addr.host_addr = 'src_addr'
        packet_type.SRC = ['src_addr']
        ntools.eq_(get_type(pkt), 'src_addr')

    @patch("lib.packet.scion.PacketType", autospec=True)
    def test_in_dst(self, packet_type):
        pkt = create_mock(['hdr'])
        pkt.hdr = create_mock(['src_addr', 'dst_addr'])
        pkt.hdr.src_addr = create_mock(['host_addr'])
        pkt.hdr.dst_addr = create_mock(['host_addr'])
        pkt.hdr.dst_addr.host_addr = 'dst_addr'
        packet_type.SRC = []
        packet_type.DST = ['dst_addr']
        ntools.eq_(get_type(pkt), 'dst_addr')

    @patch("lib.packet.scion.PacketType", autospec=True)
    def test_in_none(self, packet_type):
        pkt = create_mock(['hdr'])
        pkt.hdr = create_mock(['src_addr', 'dst_addr'])
        pkt.hdr.src_addr = create_mock(['host_addr'])
        pkt.hdr.dst_addr = create_mock(['host_addr'])
        packet_type.SRC = []
        packet_type.DST = []
        ntools.eq_(get_type(pkt), packet_type.DATA)


class TestSCIONCommonHdrInit(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.__init__
    """
    @patch("lib.packet.scion.SCIONCommonHdr.parse", autospec=True)
    @patch("lib.packet.scion.HeaderBase.__init__", autospec=True,
           return_value=None)
    def test_basic(self, super_init, parse):
        print(dir(super_init))
        hdr = SCIONCommonHdr()
        super_init.assert_called_once_with(hdr)
        ntools.eq_(hdr.version, 0)
        ntools.eq_(hdr.src_addr_type, None)
        ntools.eq_(hdr.src_addr_len, 0)
        ntools.eq_(hdr.dst_addr_type, None)
        ntools.eq_(hdr.dst_addr_len, 0)
        ntools.eq_(hdr.total_len, 0)
        ntools.eq_(hdr._iof_idx, 0)
        ntools.eq_(hdr._hof_idx, 0)
        ntools.eq_(hdr.next_hdr, 0)
        ntools.eq_(hdr.hdr_len, 0)
        ntools.assert_false(parse.called)

    @patch("lib.packet.scion.SCIONCommonHdr.parse", autospec=True)
    @patch("lib.packet.scion.HeaderBase.__init__", autospec=True,
           return_value=None)
    def test_raw(self, super_init, parse):
        hdr = SCIONCommonHdr('data')
        parse.assert_called_once_with(hdr, 'data')


class TestSCIONCommonHdrFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.from_values
    """
    def test(self):
        # Setup
        src = MagicMock(SCIONAddr)
        src.host_addr = create_mock(["TYPE"])
        src.__len__.return_value = 4
        dst = MagicMock(SCIONAddr)
        dst.host_addr = create_mock(["TYPE"])
        dst.__len__.return_value = 8
        # Call
        hdr = SCIONCommonHdr.from_values(src, dst, 3)
        # Tests
        ntools.assert_is_instance(hdr, SCIONCommonHdr)
        ntools.eq_(hdr.src_addr_type, src.host_addr.TYPE)
        ntools.eq_(hdr.src_addr_len, 4)
        ntools.eq_(hdr.dst_addr_type, dst.host_addr.TYPE)
        ntools.eq_(hdr.dst_addr_len, 8)
        ntools.eq_(hdr.next_hdr, 3)
        ntools.eq_(hdr.hdr_len, SCIONCommonHdr.LEN + 4 + 8)
        ntools.eq_(hdr.total_len, SCIONCommonHdr.LEN + 4 + 8)


class TestSCIONCommonHdrParse(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.parse
    """
    @patch("lib.packet.scion.haddr_get_type", autospec=True)
    @patch("lib.packet.scion.Raw", autospec=True)
    @patch("lib.packet.scion.SCIONCommonHdr.__init__", autospec=True,
           return_value=None)
    def test(self, init, raw, get_type):
        # Setup
        inst = SCIONCommonHdr()
        data = create_mock(["pop"])
        data.pop.return_value = bytes([0b11110000, 0b00111111]) + \
            bytes.fromhex('0304 38 40 07 08')
        raw.return_value = data
        src = create_mock(["LEN"])
        src.LEN = 8
        dst = create_mock(["LEN"])
        dst.LEN = 24
        # Need special handling for setting side_effects on autospec'd mocks
        # (https://bugs.python.org/issue17826)
        get_type.side_effect = iter([src, dst])
        # Call
        inst.parse("data")
        # Tests
        raw.assert_called_once_with("data", "SCIONCommonHdr", inst.LEN)
        ntools.eq_(inst.total_len, 0x0304)
        ntools.eq_(inst.next_hdr, 0x07)
        ntools.eq_(inst.hdr_len, 0x08)
        ntools.eq_(inst.version, 0b1111)
        ntools.eq_(inst.src_addr_type, 0b000000)
        ntools.eq_(inst.src_addr_len, ISD_AD.LEN + 8)
        ntools.eq_(inst.dst_addr_type, 0b111111)
        ntools.eq_(inst.dst_addr_len, ISD_AD.LEN + 24)
        ntools.eq_(inst._iof_idx, 1)
        ntools.eq_(inst._hof_idx, 2)


class TestSCIONCommonHdrPack(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.pack
    """
    @patch("lib.packet.scion.SCIONCommonHdr.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        hdr = SCIONCommonHdr()
        hdr.version = 0b1111
        hdr.src_addr_type = 0b000000
        hdr.src_addr_len = ISD_AD.LEN + 8
        hdr.dst_addr_type = 0b111111
        hdr.dst_addr_len = ISD_AD.LEN + 24
        hdr.total_len = 0x304
        hdr._iof_idx = 1
        hdr._hof_idx = 2
        hdr.next_hdr = 0x7
        hdr.hdr_len = 0x8
        packed = bytes([0b11110000, 0b00111111]) + \
            bytes.fromhex('0304 38 40 07 08')
        ntools.eq_(hdr.pack(), packed)


class TestSCIONCommonHdrGetOfIdxs(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.get_of_idxs
    """
    @patch("lib.packet.scion.SCIONCommonHdr.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = SCIONCommonHdr()
        inst._iof_idx = 42
        inst._hof_idx = 73
        # Call
        ntools.eq_(inst.get_of_idxs(), (42, 73))


class TestSCIONCommonHdrSetOfIdxs(object):
    """
    Unit tests for lib.packet.scion.SCIONCommonHdr.set_of_idxs
    """
    @patch("lib.packet.scion.SCIONCommonHdr.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = SCIONCommonHdr()
        inst._iof_idx = 42
        inst._hof_idx = 73
        # Call
        inst.set_of_idxs(11, 23)
        # Tests
        ntools.eq_(inst._iof_idx, 11)
        ntools.eq_(inst._hof_idx, 23)


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
        ntools.eq_(hdr.extension_hdrs, [])
        ntools.eq_(hdr.l4_proto, L4_DEFAULT)

    @patch("lib.packet.scion.HeaderBase.__init__", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.parse", autospec=True)
    def test_with_args(self, parse, hdr_init):
        hdr = SCIONHeader('data')
        hdr_init.assert_called_once_with(hdr)
        parse.assert_called_once_with(hdr, 'data')


class TestSCIONHeaderFromValues(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.from_values
    """
    def test_bad_path(self):
        src = MagicMock(spec_set=SCIONAddr)
        dst = MagicMock(spec_set=SCIONAddr)
        ntools.assert_raises(AssertionError, SCIONHeader.from_values, src,
                             dst, path='path')

    @patch("lib.packet.scion.SCIONHeader.add_extensions", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.set_path", autospec=True)
    @patch("lib.packet.scion.SCIONCommonHdr.from_values",
           new_callable=create_mock)
    @patch("lib.packet.scion.SCIONHeader.__init__", autospec=True,
           return_value=None)
    def test_full(self, init, scion_common_hdr, set_path, add_extensions):
        src = MagicMock(spec_set=SCIONAddr)
        dst = MagicMock(spec_set=SCIONAddr)
        path = MagicMock(spec_set=PathBase)
        ext_hdrs = [create_mock(['EXT_CLASS'])]
        ext_hdrs[0].EXT_CLASS = 12
        # Call
        hdr = SCIONHeader.from_values(src, dst, path, ext_hdrs, 34)
        # Tests
        ntools.assert_is_instance(hdr, SCIONHeader)
        scion_common_hdr.assert_called_once_with(src, dst, 12)
        ntools.eq_(hdr.common_hdr, scion_common_hdr.return_value)
        ntools.eq_(hdr.src_addr, src)
        ntools.eq_(hdr.dst_addr, dst)
        ntools.eq_(hdr.l4_proto, 34)
        set_path.assert_called_once_with(hdr, path)
        add_extensions.assert_called_once_with(hdr, ext_hdrs)

    @patch("lib.packet.scion.SCIONHeader.add_extensions", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.set_path", autospec=True)
    @patch("lib.packet.scion.SCIONCommonHdr.from_values",
           spec_set=SCIONCommonHdr.from_values)
    @patch("lib.packet.scion.SCIONHeader.__init__", autospec=True,
           return_value=None)
    def test_less_args(self, init, scion_common_hdr, set_path, add_extensions):
        src = MagicMock(spec_set=SCIONAddr)
        dst = MagicMock(spec_set=SCIONAddr)
        # Call
        hdr = SCIONHeader.from_values(src, dst)
        # Tests
        scion_common_hdr.assert_called_once_with(src, dst, L4_DEFAULT)
        set_path.assert_called_once_with(hdr, None)
        add_extensions.assert_called_once_with(hdr, [])


class TestSCIONHeaderAddExtensions(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.add_extensions
    """

    @patch("lib.packet.scion.SCIONHeader._set_next_hdrs", autospec=True)
    def test_add_extensions(self, _set_next_hdrs):
        hdr = SCIONHeader()
        hdr.common_hdr = MagicMock(spec_set=['total_len'])
        hdr.common_hdr.total_len = 0
        hdr.add_extensions(['ext_hdr1', 'ext_hdr2'])
        ntools.eq_(hdr.extension_hdrs, ['ext_hdr1', 'ext_hdr2'])
        ntools.eq_(hdr.common_hdr.total_len, 16)
        _set_next_hdrs.assert_called_once_with(hdr)


class TestSCIONHeaderGetPath(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.get_path
    """
    def test_getter(self):
        hdr = SCIONHeader()
        hdr._path = 'path'
        ntools.eq_(hdr.get_path(), 'path')


class TestSCIONHeaderSetPath(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.set_path
    """
    @patch("lib.packet.scion.SCIONHeader.__init__", autospec=True,
           return_value=None)
    def test_to_none(self, init):
        inst = SCIONHeader()
        inst._path = create_mock(['pack'])
        inst._path.pack.return_value = b'old_path'
        inst.common_hdr = create_mock(['hdr_len', 'total_len'])
        inst.common_hdr.hdr_len = 100
        inst.common_hdr.total_len = 200
        # Call
        inst.set_path(None)
        # Tests
        ntools.eq_(inst.common_hdr.hdr_len, 100 - len(b'old_path'))
        ntools.eq_(inst.common_hdr.total_len, 200 - len(b'old_path'))
        ntools.assert_is_none(inst._path)

    @patch("lib.packet.scion.SCIONHeader.__init__", autospec=True,
           return_value=None)
    def test_from_none(self, init):
        inst = SCIONHeader()
        inst._path = None
        inst.common_hdr = create_mock(['hdr_len', 'total_len'])
        inst.common_hdr.hdr_len = 100
        inst.common_hdr.total_len = 200
        path = create_mock(['pack'])
        path.pack.return_value = b'packed_path'
        # Call
        inst.set_path(path)
        # Tests
        ntools.eq_(inst._path, path)
        path.pack.assert_called_once_with()
        ntools.eq_(inst.common_hdr.hdr_len, 100 + len(b'packed_path'))
        ntools.eq_(inst.common_hdr.total_len, 200 + len(b'packed_path'))


class TestSCIONHeaderParse(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.parse
    """
    @patch("lib.packet.scion.Raw", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.__init__", autospec=True,
           return_value=None)
    def test(self, init, raw):
        inst = SCIONHeader()
        inst._parse_common_hdr = create_mock()
        inst._parse_opaque_fields = create_mock()
        inst._parse_extension_hdrs = create_mock()
        data = create_mock(["offset"])
        raw.return_value = data
        # Call
        ntools.eq_(inst.parse("data"), data.offset.return_value)
        # Tests
        raw.assert_called_once_with("data", "SCIONHeader", inst.MIN_LEN,
                                    min_=True)
        inst._parse_common_hdr.assert_called_once_with(data)
        inst._parse_opaque_fields.assert_called_once_with(data)
        inst._parse_extension_hdrs.assert_called_once_with(data)


class TestSCIONHeaderParseCommonHdr(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader._parse_common_hdr
    """
    @patch("lib.packet.scion.SCIONAddr", autospec=True)
    @patch("lib.packet.scion.SCIONCommonHdr", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.__init__", autospec=True,
           return_value=None)
    def test(self, init, scion_common_hdr, scion_addr):
        # Setup
        inst = SCIONHeader()
        data = create_mock(["pop"])
        data.pop.side_effect = ("pop hdr", "pop src", "pop dst")
        common_hdr = create_mock(['src_addr_type', 'src_addr_len',
                                  'dst_addr_type', 'dst_addr_len'])
        scion_common_hdr.return_value = common_hdr
        scion_common_hdr.LEN = 2
        scion_addr.side_effect = ['src_addr', 'dst_addr']
        # Call
        inst._parse_common_hdr(data)
        # Tests
        scion_common_hdr.assert_called_once_with("pop hdr")
        ntools.eq_(inst.common_hdr, common_hdr)
        assert_these_calls(scion_addr, [
            call((common_hdr.src_addr_type, "pop src")),
            call((common_hdr.dst_addr_type, "pop dst")),
        ])
        ntools.eq_(inst.src_addr, 'src_addr')
        ntools.eq_(inst.dst_addr, 'dst_addr')


class TestSCIONHeaderParseOpaqueFields(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader._parse_opaque_fields
    """
    @patch("lib.packet.scion.EmptyPath", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.__init__", autospec=True,
           return_value=None)
    def test_empty_path(self, inst, empty_path):
        inst = SCIONHeader()
        inst.common_hdr = create_mock(['hdr_len'])
        inst.common_hdr.hdr_len = 123
        data = create_mock(['offset'])
        data.offset.return_value = 123
        # Call
        inst._parse_opaque_fields(data)
        # Tests
        ntools.eq_(inst._path, empty_path.return_value)

    @patch("lib.packet.scion.InfoOpaqueField", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.__init__", autospec=True,
           return_value=None)
    def _check(self, oft, path, init, iof):
        inst = SCIONHeader()
        inst.common_hdr = create_mock(['get_of_idxs', 'hdr_len'])
        inst.common_hdr.get_of_idxs.return_value = (42, 50)
        iof.return_value = create_mock(['info'])
        iof.return_value.info = oft
        data = create_mock(['offset', 'get', 'pop'])
        path.return_value = create_mock(["set_of_idxs"])
        # Call
        inst._parse_opaque_fields(data)
        # Tests
        iof.assert_called_once_with(data.get.return_value)
        path.assert_called_once_with(data.pop.return_value)
        ntools.eq_(inst._path, path.return_value)
        path.return_value.set_of_idxs.assert_called_once_with(42, 50)

    @patch("lib.packet.scion.CorePath", autospec=True)
    def test_core(self, core):
        self._check(OFT.CORE, core)

    @patch("lib.packet.scion.CrossOverPath", autospec=True)
    def test_crossover(self, crossover):
        self._check(OFT.SHORTCUT, crossover)

    @patch("lib.packet.scion.PeerPath", autospec=True)
    def test_peer_intra(self, peer):
        self._check(OFT.INTRA_ISD_PEER, peer)

    @patch("lib.packet.scion.PeerPath", autospec=True)
    def test_peer_inter(self, peer):
        self._check(OFT.INTER_ISD_PEER, peer)

    @patch("lib.packet.scion.InfoOpaqueField", autospec=True)
    def test_unknown_type(self, iof):
        # Setup
        hdr = SCIONHeader()
        hdr.common_hdr = create_mock(['hdr_len'])
        iof.return_value = create_mock(['info'])
        iof.return_value.info = 34
        data = create_mock(['offset', 'get', 'pop'])
        # Call
        ntools.assert_raises(SCIONParseError, hdr._parse_opaque_fields, data)


class TestSCIONHeaderPack(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.pack
    """
    @patch("lib.packet.scion.SCIONHeader.__init__", autospec=True,
           return_value=None)
    def _check(self, with_path, ext_hdrs, init):
        packed = [b'common_hdr', b'src_addr', b'dst_addr']
        inst = SCIONHeader()
        inst._path = None
        if with_path:
            path = create_mock(["get_of_idxs", "pack"])
            path.get_of_idxs.return_value = 42, 53
            packed_path = b'path'
            path.pack.return_value = packed_path
            packed.append(packed_path)
            inst._path = path
        inst.common_hdr = create_mock(['pack', 'set_of_idxs'])
        inst.common_hdr.pack.return_value = b'common_hdr'
        inst.src_addr = create_mock(['pack'])
        inst.src_addr.pack.return_value = b'src_addr'
        inst.dst_addr = create_mock(['pack'])
        inst.dst_addr.pack.return_value = b'dst_addr'
        inst.extension_hdrs = []
        for i in range(ext_hdrs):
            ext_hdr = create_mock(['pack'])
            val = b'ext_hdr' + str.encode(str(i))
            ext_hdr.pack.return_value = val
            packed.append(val)
            inst.extension_hdrs.append(ext_hdr)
        # Call
        ntools.eq_(inst.pack(), b"".join(packed))
        # Tests
        if with_path:
            inst.common_hdr.set_of_idxs.assert_called_once_with(
                *inst._path.get_of_idxs.return_value)

    def test(self):
        for with_path, ext_hdrs in (
            (False, 0), (True, 0), (False, 3), (True, 3),
        ):
            yield self._check, with_path, ext_hdrs


class TestSCIONHeaderReverse(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.reverse
    """
    @patch("lib.packet.scion.SCIONHeader.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = SCIONHeader()
        inst.src_addr = 'src_addr'
        inst.dst_addr = 'dst_addr'
        inst._path = create_mock(['reverse'])
        # Call
        inst.reverse()
        # Tests
        ntools.eq_(inst.src_addr, 'dst_addr')
        ntools.eq_(inst.dst_addr, 'src_addr')
        inst._path.reverse.assert_called_once_with()


class TestSCIONHeaderLen(object):
    """
    Unit tests for lib.packet.scion.SCIONHeader.__len__
    """
    @patch("lib.packet.scion.SCIONHeader.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = SCIONHeader()
        inst.common_hdr = create_mock(['hdr_len'])
        inst.common_hdr.hdr_len = 123
        inst.extension_hdrs = ['ext_hdr0', 'ext_hdr01']
        ntools.eq_(len(inst), 123 + len('ext_hdr0') + len('ext_hdr01'))


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
    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    def test_basic(self, scion_hdr, set_payload):
        hdr = create_mock(["l4_proto"])
        scion_hdr.return_value = hdr
        packet = SCIONPacket.from_values('src', 'dst', 'payload', 'path',
                                         'ext_hdrs', 'next_hdr')
        ntools.assert_is_instance(packet, SCIONPacket)
        scion_hdr.assert_called_once_with('src', 'dst', 'path', 'ext_hdrs',
                                          'next_hdr')
        ntools.eq_(packet.hdr, hdr)
        set_payload.assert_called_once_with(packet, 'payload')

    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    def test_less_args(self, scion_hdr, set_payload):
        hdr = create_mock(["l4_proto"])
        scion_hdr.return_value = hdr
        SCIONPacket.from_values('src', 'dst', 'payload')
        scion_hdr.assert_called_once_with('src', 'dst', None, None, L4_DEFAULT)


class TestSCIONPacketSetPayload(object):
    """
    Unit tests for lib.packet.scion.SCIONPacket.set_payload
    """
    @patch("lib.packet.scion.PacketBase.set_payload", autospec=True)
    def test(self, set_payload):
        packet = SCIONPacket()
        packet.hdr = MagicMock(spec_set=['common_hdr', '__len__'])
        packet.hdr.__len__.return_value = 123
        packet.hdr.common_hdr = MagicMock(spec_set=['total_len'])
        packet.set_payload('payload')
        set_payload.assert_called_once_with(packet, 'payload')
        ntools.eq_(packet.payload_len, 7)
        ntools.eq_(packet.hdr.common_hdr.total_len, 130)


class TestSCIONPacketParse(object):
    """
    Unit tests for lib.packet.scion.SCIONPacket.parse
    """
    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONHeader", autospec=True)
    @patch("lib.packet.scion.Raw", autospec=True)
    def _check(self, payload, proto, raw, scion_hdr, set_payload):
        # Setup
        packet = SCIONPacket()
        data = MagicMock(spec_set=["__len__", "get", "pop"])
        data.__len__.return_value = 42
        data.get.return_value = "get hdr"
        data.pop.return_value = "pop payload"
        raw.return_value = data
        hdr = create_mock(["__len__", "dst_addr", "l4_proto", "src_addr"])
        hdr.l4_proto = proto
        hdr.src_addr = "src_addr"
        hdr.dst_addr = "dst_addr"
        scion_hdr.return_value = hdr
        # Call
        packet.parse(b"data")
        # Tests
        ntools.eq_(packet.raw, b"data")
        raw.assert_called_once_with(b"data", "SCIONPacket", packet.MIN_LEN,
                                    min_=True)
        scion_hdr.assert_called_once_with("get hdr")
        ntools.eq_(packet.hdr, scion_hdr.return_value)
        ntools.eq_(packet.payload_len, 42)
        set_payload.assert_called_once_with(packet, payload)

    def test_basic(self):
        self._check("pop payload", L4_RESERVED)

    @patch("lib.packet.scion.SCIONUDPPacket", autospec=True)
    def test_udp(self, udp):
        udp.return_value = "udp payload"
        self._check("udp payload", L4_UDP)
        udp.assert_called_once_with(("src_addr", "dst_addr", "pop payload"))


class TestSCIONPacketPack(object):
    """
    Unit tests for lib.packet.scion.SCIONPacket.pack
    """
    def test_payload_packetbase(self):
        packet = SCIONPacket()
        packet.hdr = MagicMock(spec_set=['pack'])
        packet.hdr.pack.return_value = b'packed_hdr'
        packet._payload = MagicMock(spec_set=SCIONPacket)
        packet._payload.pack.return_value = b'packed_payload'
        ntools.eq_(packet.pack(), b'packed_hdrpacked_payload')

    def test_payload_bytes(self):
        packet = SCIONPacket()
        packet.hdr = MagicMock(spec_set=['pack'])
        packet.hdr.pack.return_value = b'packed_hdr'
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
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    @patch("lib.packet.scion.SCIONAddr.from_values",
           spec_set=SCIONAddr.from_values)
    def test(self, scion_addr, scion_hdr, set_payload):
        scion_addr.return_value = 'dst'
        dst_isd_ad = MagicMock(spec_set=['isd', 'ad'])
        scion_hdr.return_value = 'hdr'
        packet = IFIDPacket.from_values('src', dst_isd_ad, 0x0102)
        ntools.assert_is_instance(packet, IFIDPacket)
        ntools.eq_(packet.request_id, 0x0102)
        scion_addr.assert_called_once_with(dst_isd_ad.isd, dst_isd_ad.ad,
                                           PacketType.IFID_PKT)
        scion_hdr.assert_called_once_with('src', 'dst')
        ntools.eq_(packet.hdr, 'hdr')
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
    @patch("lib.packet.scion.Raw", autospec=True)
    def test(self, raw, parse, isd_ad):
        # Setup
        raw.return_value = MagicMock(spec_set=["pop"])
        raw.return_value.pop.side_effect = (
            bytes.fromhex('0102'), "pop src isd_ad",
            "pop dst isd_ad", bytes.fromhex("1718191a"),
        )
        req = CertChainRequest()
        req._payload = b"payload"
        isd_ad.side_effect = [(0x0bc, 0x0021d), (0x021, 0x004c6)]
        # Call
        req.parse(b"data")
        # Tests
        parse.assert_called_once_with(req, b'data')
        raw.assert_called_once_with(b"payload", "CertChainRequest", req.LEN)
        isd_ad.assert_has_calls([call("pop src isd_ad"),
                                 call("pop dst isd_ad")])
        ntools.eq_(req.ingress_if, 0x0102)
        ntools.eq_(req.src_isd, 0x0bc)
        ntools.eq_(req.src_ad, 0x0021d)
        ntools.eq_(req.isd_id, 0x021)
        ntools.eq_(req.ad_id, 0x004c6)
        ntools.eq_(req.version, 0x1718191a)


class TestCertChainRequestFromValues(object):
    """
    Unit tests for lib.packet.scion.CertChainRequest.from_values
    """
    @patch("lib.packet.scion.ISD_AD", autospec=True)
    @patch("lib.packet.scion.CertChainRequest.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    @patch("lib.packet.scion.SCIONAddr.from_values",
           spec_set=SCIONAddr.from_values)
    def test(self, scion_addr, scion_hdr, set_payload, isd_ad):
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
        ntools.eq_(req.hdr, 'hdr')
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
    @patch("lib.packet.scion.Raw", autospec=True)
    def test(self, raw, parse, isd_ad):
        # Setup
        raw.return_value = MagicMock(spec_set=["pop"])
        raw.return_value.pop.side_effect = (
            "pop isd_ad", bytes.fromhex('01020304'), "pop chain")
        rep = CertChainReply()
        rep._payload = b"payload"
        isd_ad.return_value = (0x0bc, 0x0021d)
        # Call
        rep.parse(b'data')
        # Tests
        parse.assert_called_once_with(rep, b'data')
        raw.assert_called_once_with(b"payload", "CertChainReply", rep.MIN_LEN,
                                    min_=True)
        isd_ad.assert_called_once_with("pop isd_ad")
        ntools.eq_(rep.isd_id, 0xbc)
        ntools.eq_(rep.ad_id, 0x0021d)
        ntools.eq_(rep.version, 0x01020304)
        ntools.eq_(rep.cert_chain, "pop chain")


class TestCertChainReplyFromValues(object):
    """
    Unit tests for lib.packet.scion.CertChainReply.from_values
    """
    @patch("lib.packet.scion.ISD_AD", autospec=True)
    @patch("lib.packet.scion.CertChainReply.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    @patch("lib.packet.scion.SCIONAddr.from_values",
           spec_set=SCIONAddr.from_values)
    def test(self, scion_addr, scion_hdr, set_payload, isd_ad):
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
        ntools.eq_(rep.hdr, 'hdr')
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
    @patch("lib.packet.scion.Raw", autospec=True)
    def test(self, raw, parse, isd_ad):
        # Setup
        raw.return_value = MagicMock(spec_set=["pop"])
        raw.return_value.pop.side_effect = (
            bytes.fromhex('0102'), "pop src isd_ad",
            bytes.fromhex('0304'), bytes.fromhex("1718191a"),
        )
        req = TRCRequest()
        req._payload = b"payload"
        isd_ad.return_value = (0x001, 0x60010)
        # Call
        req.parse('data')
        # Tests
        parse.assert_called_once_with(req, 'data')
        raw.assert_called_once_with(b"payload", "TRCRequest", req.LEN)
        ntools.eq_(req.ingress_if, 0x0102)
        isd_ad.assert_called_once_with("pop src isd_ad")
        ntools.eq_(req.src_isd, 0x001)
        ntools.eq_(req.src_ad, 0x60010)
        ntools.eq_(req.isd_id, 0x0304)
        ntools.eq_(req.version, 0x1718191a)


class TestTRCRequestFromValues(object):
    """
    Unit tests for lib.packet.scion.TRCRequest.from_values
    """
    @patch("lib.packet.scion.ISD_AD", autospec=True)
    @patch("lib.packet.scion.TRCRequest.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    @patch("lib.packet.scion.SCIONAddr.from_values",
           spec_set=SCIONAddr.from_values)
    def test(self, scion_addr, scion_hdr, set_payload, isd_ad):
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
        ntools.eq_(req.hdr, 'hdr')
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
    @patch("lib.packet.scion.Raw", autospec=True)
    def test(self, raw, parse):
        # Setup
        raw.return_value = MagicMock(spec_set=["pop"])
        raw.return_value.pop.side_effect = (
            bytes.fromhex('0102 03040506'), b'\x00' * 10)
        rep = TRCReply()
        rep._payload = b"payload"
        # Call
        rep.parse('data')
        # Tests
        parse.assert_called_once_with(rep, 'data')
        raw.assert_called_once_with(b"payload", "TRCReply", rep.MIN_LEN,
                                    min_=True)
        ntools.eq_(rep.isd_id, 0x0102)
        ntools.eq_(rep.version, 0x03040506)
        ntools.eq_(rep.trc, b'\x00' * 10)


class TestTRCReplyFromValues(object):
    """
    Unit tests for lib.packet.scion.TRCReply.from_values
    """
    @patch("lib.packet.scion.TRCReply.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values",
           spec_set=SCIONHeader.from_values)
    @patch("lib.packet.scion.SCIONAddr.from_values",
           spec_set=SCIONAddr.from_values)
    def test(self, scion_addr, scion_hdr, set_payload):
        scion_addr.return_value = 'src'
        scion_hdr.return_value = 'hdr'
        (isd_id, version) = (0x0102, 0x03040506)
        dst = MagicMock(spec_set=['isd_id', 'ad_id'])
        rep = TRCReply.from_values(dst, isd_id, version, b'trc')
        ntools.assert_is_instance(rep, TRCReply)
        scion_addr.assert_called_once_with(dst.isd_id, dst.ad_id,
                                           PacketType.TRC_REP)
        scion_hdr.assert_called_once_with('src', dst)
        ntools.eq_(rep.hdr, 'hdr')
        ntools.eq_(rep.isd_id, isd_id)
        ntools.eq_(rep.version, version)
        ntools.eq_(rep.trc, b'trc')
        payload = bytes.fromhex('0102 03040506') + b'trc'
        set_payload.assert_called_once_with(rep, payload)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
