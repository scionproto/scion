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
mod:`path_transport_test` --- lib.packet.ext.path_transport unit tests
======================================================================
"""
# Stdlib
from unittest.mock import patch, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.packet.ext.path_transport import (
    PathTransportExt,
    PathTransOFPath,
    PathTransType,
)
from lib.packet.opaque_field import OpaqueField
from test.testcommon import (
    assert_these_calls,
    create_mock,
)


class TestPathTransOFPathParse(object):
    """
    Unit tests for lib.packet.ext.path_transport.PathTransOFPath._parse
    """
    @patch("lib.packet.ext.path_transport.parse_path", autospec=True)
    @patch("lib.packet.ext.path_transport.SCIONAddr", autospec=True)
    @patch("lib.packet.ext.path_transport.Raw", autospec=True)
    def test(self, raw, scion_addr, parse_path):
        inst = PathTransOFPath()
        data = create_mock(["pop", "get", "__len__"])
        data.pop.side_effect = "src_type", "dst_type", None, None, "path"
        data.get.side_effect = "src_addr", "dst_addr"
        data.__len__.return_value = 22
        raw.return_value = data
        scion_addr.side_effect = "scion_src_addr", "scion_dst_addr"
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.MIN_LEN, min_=True)
        ntools.eq_(inst.src, "scion_src_addr")
        ntools.eq_(inst.dst, "scion_dst_addr")
        assert_these_calls(scion_addr, [call(("src_type", "src_addr")),
                                        call(("dst_type", "dst_addr"))])
        parse_path.assert_called_once_with("path")
        data.pop.assert_called_with(22 - (22 % OpaqueField.LEN))


class TestPathTransportExtFromValues(object):
    """
    Unit tests for lib.packet.ext.path_transport.PathTransportExt.from_values
    """
    @patch("lib.packet.ext.path_transport.PathTransportExt._init_size",
           autospec=True)
    def _check(self, plen, expected, init_size):
        path = create_mock(["pack"])
        path.pack.return_value = bytes(range(plen))
        # Call
        inst = PathTransportExt.from_values("path_type", path)
        # Tests
        ntools.eq_(inst.path_type, "path_type")
        ntools.eq_(inst.path, path)
        init_size.assert_called_once_with(inst, expected)

    def test(self):
        for plen, expected in (
            (0, 0), (1, 0), (3, 0), (4, 0), (5, 1), (11, 1), (12, 1), (13, 2),
        ):
            yield self._check, plen, expected


class TestPathTransportExtParse(object):
    """
    Unit tests for lib.packet.ext.path_transport.PathTransportExt._parse
    """
    @patch("lib.packet.ext.path_transport.PathTransOFPath", autospec=True)
    @patch("lib.packet.ext.path_transport.EndToEndExtension._parse",
           autospec=True)
    @patch("lib.packet.ext.path_transport.Raw", autospec=True)
    def test_of_type(self, raw, super_parse, of_path):
        data = create_mock(["pop", "__len__"])
        data.pop.side_effect = PathTransType.OF_PATH, b"of_path"
        data.__len__.return_value = 8
        raw.return_value = data
        inst = PathTransportExt()
        of_path.return_value = "parsed_of_path"
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.MIN_LEN, min_=True)
        super_parse.assert_called_once_with(inst, data)
        ntools.eq_(inst.path_type, PathTransType.OF_PATH)
        ntools.eq_(inst.path, of_path.return_value)
        of_path.assert_called_once_with(b"of_path")

    @patch("lib.packet.ext_hdr.EndToEndExtension._parse", autospec=True)
    @patch("lib.packet.ext.path_transport.PathSegment", autospec=True)
    @patch("lib.packet.ext.path_transport.Raw", autospec=True)
    def test_pcb_type(self, raw, pcb_path, super_parse):
        data = create_mock(["pop", "__len__"])
        data.pop.side_effect = PathTransType.PCB_PATH, b"pcb_path"
        data.__len__.return_value = 9
        raw.return_value = data
        inst = PathTransportExt()
        pcb_path.return_value = "parsed_pcb_path"
        # Call
        inst._parse("data")
        # Tests
        ntools.eq_(inst.path, "parsed_pcb_path")
        pcb_path.assert_called_once_with(b"pcb_path")

    @patch("lib.packet.ext_hdr.EndToEndExtension._parse", autospec=True)
    @patch("lib.packet.ext.path_transport.Raw", autospec=True)
    def test_wrong_type(self, raw, super_parse):
        data = create_mock(["pop", "__len__"])
        data.pop.return_value = 3456
        data.__len__.return_value = 1
        raw.return_value = data
        inst = PathTransportExt()
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse, "data")


class TestPathTransportExtPack(object):
    """
    Unit tests for lib.packet.ext.path_transport.PathTransportExt.pack
    """
    @patch("lib.packet.ext_hdr.ExtensionHeader._check_len", autospec=True)
    @patch("lib.packet.ext.path_transport.calc_padding", autospec=True)
    def test(self, calc_padding, check_len):
        inst = PathTransportExt()
        inst._hdr_len = 1
        inst.path_type = 1
        inst.path = create_mock(["pack"])
        inst.path.pack.return_value = b"packed_path"
        calc_padding.return_value = 1
        expected = b"\x01packed_path\x00"
        # Call
        inst.pack()
        # Tests
        calc_padding.assert_called_once_with(11 - 4, inst.LINE_LEN)
        check_len.assert_called_once_with(inst, expected)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
