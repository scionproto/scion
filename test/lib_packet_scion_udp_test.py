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
:mod:`lib_packet_scion_udp_test` --- lib.packet.scion_udp unit tests
====================================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scion_udp import (
    SCIONUDPHeader,
)
from test.testcommon import create_mock


class TestSCIONUDPHeaderInit(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPHeader.__init__
    """
    @patch("lib.packet.scion_udp.SCIONUDPHeader._parse", autospec=True)
    @patch("lib.packet.scion_udp.L4HeaderBase.__init__", autospec=True,
           return_value=None)
    def test_basic(self, super_init, parse):
        inst = SCIONUDPHeader()
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.assert_is_none(inst._src_addr)
        ntools.assert_is_none(inst.src_port)
        ntools.assert_is_none(inst._dst_addr)
        ntools.assert_is_none(inst.dst_port)
        ntools.assert_false(parse.called)

    @patch("lib.packet.scion_udp.SCIONUDPHeader._parse", autospec=True)
    @patch("lib.packet.scion_udp.L4HeaderBase.__init__", autospec=True,
           return_value=None)
    def test_raw(self, super_init, parse):
        inst = SCIONUDPHeader(raw=("src", "dst", "raw", "payload"))
        # Tests
        parse.assert_called_once_with(inst, "src", "dst", "raw", "payload")


class TestSCIONUDPHeaderFromValues(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPHeader.from_values
    """
    @patch("lib.packet.scion_udp.SCIONUDPHeader.update", autospec=True)
    def test_full(self, update):
        # Call
        inst = SCIONUDPHeader.from_values("src_addr", "src_port", "dst_addr",
                                          "dst_port", "payload")
        # Tests
        ntools.assert_is_instance(inst, SCIONUDPHeader)
        update.assert_called_once_with(inst, "src_addr", "src_port", "dst_addr",
                                       "dst_port", "payload")


class TestSCIONUDPHeaderParse(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPHeader.parse
    """
    @patch("lib.packet.scion_udp.Raw", autospec=True)
    def test_basic(self, raw):
        inst = SCIONUDPHeader()
        inst._calc_checksum = create_mock()
        inst._calc_checksum.return_value = 0x9999
        data = create_mock(["__len__", "pop"])
        data.pop.return_value = bytes.fromhex("11112222000f9999")
        raw.return_value = data
        # Call
        inst._parse("src", "dst", "raw", "payload")
        # Tests
        raw.assert_called_once_with("raw", "SCIONUDPHeader", inst.LEN)
        ntools.eq_(inst._src_addr, "src")
        ntools.eq_(inst._dst_addr, "dst")
        ntools.eq_(inst.src_port, 0x1111)
        ntools.eq_(inst.dst_port, 0x2222)
        ntools.eq_(inst._length, 0x000F)
        ntools.eq_(inst._checksum, 0x9999)

    @patch("lib.packet.scion_udp.Raw", autospec=True)
    def test_bad_length(self, raw):
        inst = SCIONUDPHeader()
        data = create_mock(["__len__", "pop"])
        data.pop.return_value = bytes.fromhex("11112222000e9999")
        raw.return_value = data
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse, "src", "dst", "raw",
                             "payload")

    @patch("lib.packet.scion_udp.Raw", autospec=True)
    def test_bad_checksum(self, raw):
        inst = SCIONUDPHeader()
        inst._calc_checksum = create_mock()
        inst._calc_checksum.return_value = 0x8888
        data = create_mock(["__len__", "pop"])
        data.pop.return_value = bytes.fromhex("11112222000f9999")
        raw.return_value = data
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse, "src", "dst", "raw",
                             "payload")


class TestSCIONUDPHeaderUpdate(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPHeader.update
    """
    @patch("lib.packet.scion_udp.SCIONUDPHeader._calc_checksum", autospec=True)
    def test_full(self, calc_chksm):
        inst = SCIONUDPHeader()
        calc_chksm.return_value = 0x9999
        payload = create_mock(["total_len"])
        payload.total_len.return_value = 9
        # Call
        inst.update(src_addr="src addr", src_port=0x1111, dst_addr="dst addr",
                    dst_port=0x2222, payload=payload)
        # Tests
        ntools.eq_(inst._src_addr, "src addr")
        ntools.eq_(inst.src_port, 0x1111)
        ntools.eq_(inst._dst_addr, "dst addr")
        ntools.eq_(inst.dst_port, 0x2222)
        ntools.eq_(inst._length, inst.LEN + 9)
        ntools.eq_(inst._checksum, 0x9999)


class TestSCIONUDPHeaderCalcChecksum(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPHeader._calc_checksum
    """
    @patch("lib.packet.scion_udp.scapy.utils.checksum", autospec=True)
    def test(self, scapy_checksum):
        inst = SCIONUDPHeader()
        inst._src_addr = create_mock(["pack"], class_=SCIONAddr)
        inst._src_addr.pack.return_value = b"source address"
        inst._dst_addr = create_mock(["pack"], class_=SCIONAddr)
        inst._dst_addr.pack.return_value = b"destination address"
        inst.src_port = 0x1111
        inst.dst_port = 0x2222
        inst._length = 2 + 7
        payload = create_mock(["pack_full"])
        payload.pack_full.return_value = b"payload"
        expected_call = b"".join([
            b"source address",
            b"destination address",
            bytes.fromhex("11 1111 2222 0009"),
            b"payload",
        ])
        # Call
        ntools.eq_(inst._calc_checksum(payload), scapy_checksum.return_value)
        # Tests
        scapy_checksum.assert_called_once_with(expected_call)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
