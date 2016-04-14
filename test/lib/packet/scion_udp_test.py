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
from lib.errors import SCIONChecksumFailed
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scion_udp import (
    SCIONUDPHeader,
)
from lib.packet.scmp.errors import SCMPBadPktLen
from lib.types import L4Proto
from test.testcommon import create_mock


class TestSCIONUDPHeaderParse(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPHeader._parse
    """
    @patch("lib.packet.scion_udp.Raw", autospec=True)
    def test(self, raw):
        inst = SCIONUDPHeader()
        data = create_mock(["pop"])
        data.pop.return_value = bytes.fromhex("11112222000f9999")
        raw.return_value = data
        # Call
        inst._parse("src", "dst", "raw")
        # Tests
        raw.assert_called_once_with("raw", inst.NAME, inst.LEN)
        ntools.eq_(inst._src, "src")
        ntools.eq_(inst._dst, "dst")
        ntools.eq_(inst.src_port, 0x1111)
        ntools.eq_(inst.dst_port, 0x2222)
        ntools.eq_(inst._length, 0x000F)
        ntools.eq_(inst._checksum, bytes.fromhex("9999"))


class TestSCIONUDPHeaderUpdate(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPHeader.update
    """
    def test_full(self):
        inst = SCIONUDPHeader()
        inst._calc_checksum = create_mock()
        inst._calc_checksum.return_value = 0x9999
        payload = create_mock(["total_len"])
        payload.total_len.return_value = 9
        # Call
        inst.update(src="src addr", src_port=0x1111, dst="dst addr",
                    dst_port=0x2222, payload=payload)
        # Tests
        ntools.eq_(inst._src, "src addr")
        ntools.eq_(inst.src_port, 0x1111)
        ntools.eq_(inst._dst, "dst addr")
        ntools.eq_(inst.dst_port, 0x2222)
        ntools.eq_(inst._length, inst.LEN + 9)
        inst._calc_checksum.assert_called_once_with(payload)
        ntools.eq_(inst._checksum, 0x9999)


class TestSCIONUDPHeaderValidate(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPHeader.validate
    """
    @patch("lib.packet.scion_udp.Raw", autospec=True)
    def test_bad_length(self, raw):
        inst = SCIONUDPHeader()
        inst._length = 10
        # Call
        ntools.assert_raises(SCMPBadPktLen, inst.validate, range(9))

    @patch("lib.packet.scion_udp.Raw", autospec=True)
    def test_bad_checksum(self, raw):
        inst = SCIONUDPHeader()
        inst._length = 10 + inst.LEN
        inst._calc_checksum = create_mock()
        inst._calc_checksum.return_value = bytes.fromhex("8888")
        inst._checksum = bytes.fromhex("9999")
        # Call
        ntools.assert_raises(SCIONChecksumFailed, inst.validate, range(10))


class TestSCIONUDPHeaderCalcChecksum(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPHeader._calc_checksum
    """
    @patch("lib.packet.scion_udp.scapy.utils.checksum", autospec=True)
    def test(self, scapy_checksum):
        inst = SCIONUDPHeader()
        inst._src = create_mock(["pack"], class_=SCIONAddr)
        inst._src.pack.return_value = b"source address"
        inst._dst = create_mock(["pack"], class_=SCIONAddr)
        inst._dst.pack.return_value = b"destination address"
        inst.pack = create_mock()
        inst.pack.return_value = b"packed with null checksum"
        payload = create_mock(["pack_full"])
        payload.pack_full.return_value = b"payload"
        expected_call = b"".join([
            b"source address", b"destination address", bytes([L4Proto.UDP]),
            b"packed with null checksum", b"payload",
        ])
        scapy_checksum.return_value = 0x3412
        # Call
        ntools.eq_(inst._calc_checksum(payload), bytes.fromhex("1234"))
        # Tests
        scapy_checksum.assert_called_once_with(expected_call)


class TestSCIONUDPHeaderReverse(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPHeader.reverse
    """
    def test(self):
        inst = SCIONUDPHeader()
        inst._src = "src addr"
        inst._dst = "dst addr"
        inst.src_port = "src port"
        inst.dst_port = "dst port"
        # Call
        inst.reverse()
        # Tests
        ntools.eq_(inst._src, "dst addr")
        ntools.eq_(inst._dst, "src addr")
        ntools.eq_(inst.src_port, "dst port")
        ntools.eq_(inst.dst_port, "src port")

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
