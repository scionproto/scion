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
from lib.packet.scion_udp import (
    SCIONUDPPacket,
)
from test.testcommon import create_mock


class TestSCIONUDPPacketInit(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPPacket.__init__
    """
    @patch("lib.packet.scion_udp.SCIONUDPPacket.parse", autospec=True)
    @patch("lib.packet.scion_udp.PacketBase.__init__", autospec=True,
           return_value=None)
    def test_basic(self, super_init, parse):
        # Call
        inst = SCIONUDPPacket()
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.assert_is_none(inst._src_addr)
        ntools.assert_is_none(inst.src_port)
        ntools.assert_is_none(inst._dst_addr)
        ntools.assert_is_none(inst.dst_port)
        ntools.assert_false(parse.called)

    @patch("lib.packet.scion_udp.SCIONUDPPacket.parse", autospec=True)
    @patch("lib.packet.scion_udp.PacketBase.__init__", autospec=True,
           return_value=None)
    def test_raw(self, super_init, parse):
        # Call
        inst = SCIONUDPPacket(raw=("src", "dst", "raw"))
        # Tests
        parse.assert_called_once_with(inst, "src", "dst", "raw")


class TestSCIONUDPPacketFromValues(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPPacket.from_values
    """
    @patch("lib.packet.scion_udp.SCIONUDPPacket.set_payload", autospec=True)
    @patch("lib.packet.scion_udp.SCIONUDPPacket.__init__", autospec=True,
           return_value=None)
    def test_full(self, init, set_payload):
        # Call
        inst = SCIONUDPPacket.from_values("src_addr", "src_port", "dst_addr",
                                          "dst_port", "payload")
        # Tests
        init.assert_called_once_with(inst)
        ntools.eq_(inst._src_addr, "src_addr")
        ntools.eq_(inst.src_port, "src_port")
        ntools.eq_(inst._dst_addr, "dst_addr")
        ntools.eq_(inst.dst_port, "dst_port")
        set_payload.assert_called_once_with(inst, "payload")


class TestSCIONUDPPacketParse(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPPacket.parse
    """
    @patch("lib.packet.scion_udp.Raw", autospec=True)
    @patch("lib.packet.scion_udp.SCIONUDPPacket.__init__", autospec=True,
           return_value=None)
    def test_basic(self, init, raw):
        inst = SCIONUDPPacket()
        data = raw.return_value
        data.pop.side_effect = [bytes.fromhex("0102030405060708"), "payload"]
        data.__len__.return_value = 0x0506 - inst.HDR_LEN
        inst.set_payload = create_mock()
        # Call
        inst.parse("src", "dst", "raw")
        # Tests
        raw.assert_called_once_with("raw", "SCIONUDPPacket", inst.MIN_LEN,
                                    min_=True)
        ntools.eq_(inst._src_addr, "src")
        ntools.eq_(inst._dst_addr, "dst")
        ntools.eq_(inst.src_port, 0x0102)
        ntools.eq_(inst.dst_port, 0x0304)
        inst.set_payload.assert_called_once_with("payload", expected=0x0708)

    @patch("lib.packet.scion_udp.Raw", autospec=True)
    @patch("lib.packet.scion_udp.SCIONUDPPacket.__init__", autospec=True,
           return_value=None)
    def test_bad_length(self, init, raw):
        inst = SCIONUDPPacket()
        data = raw.return_value
        data.pop.side_effect = [bytes.fromhex("0102030405060708"), "payload"]
        data.__len__.return_value = 0x0507
        # Call
        ntools.assert_raises(SCIONParseError, inst.parse, "src", "dst", "raw")


class TestSCIONUDPPacketPack(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPPacket.pack
    """
    @patch("lib.packet.scion_udp.SCIONUDPPacket.__len__", autospec=True,
           return_value=None)
    @patch("lib.packet.scion_udp.SCIONUDPPacket.__init__", autospec=True,
           return_value=None)
    def test(self, init, len_):
        inst = SCIONUDPPacket()
        inst._calc_checksum = create_mock()
        inst._calc_checksum.return_value = 0x0708
        inst._payload = b"payload"
        inst.src_port = 0x0102
        inst.dst_port = 0x0304
        len_.return_value = 0x0506
        expected = bytes.fromhex("0102030405060708") + inst._payload
        # Call
        ntools.eq_(inst.pack(), expected)


class TestSCIONUDPPacketSetPayload(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPPacket.set_payload
    """
    @patch("lib.packet.scion_udp.PacketBase.set_payload", autospec=True)
    @patch("lib.packet.scion_udp.SCIONUDPPacket.__init__", autospec=True,
           return_value=None)
    def test_basic(self, init, pb_set_pld):
        inst = SCIONUDPPacket()
        inst._calc_checksum = create_mock()
        # Call
        inst.set_payload("payload")
        # Tests
        pb_set_pld.assert_called_once_with(inst, "payload")
        ntools.assert_false(inst._calc_checksum.called)

    @patch("lib.packet.scion_udp.PacketBase.set_payload", autospec=True)
    @patch("lib.packet.scion_udp.SCIONUDPPacket.__init__", autospec=True,
           return_value=None)
    def test_expected_match(self, init, pb_set_pld):
        inst = SCIONUDPPacket()
        inst._calc_checksum = create_mock()
        # Call
        inst.set_payload("payload", expected=inst._calc_checksum.return_value)
        # Tests
        inst._calc_checksum.assert_called_once_with()

    @patch("lib.packet.scion_udp.PacketBase.set_payload", autospec=True)
    @patch("lib.packet.scion_udp.SCIONUDPPacket.__init__", autospec=True,
           return_value=None)
    def test_expected_fail(self, init, pb_set_pld):
        inst = SCIONUDPPacket()
        inst._calc_checksum = create_mock()
        # Call
        ntools.assert_raises(SCIONParseError, inst.set_payload, "payload",
                             expected="expected")


class TestSCIONUDPPacketCalcChecksum(object):
    """
    Unit tests for lib.packet.scion_udp.SCIONUDPPacket._calc_checksum
    """
    @patch("lib.packet.scion_udp.scapy.utils.checksum", autospec=True)
    @patch("lib.packet.scion_udp.SCIONUDPPacket.__len__", autospec=True)
    @patch("lib.packet.scion_udp.SCIONUDPPacket.__init__", autospec=True,
           return_value=None)
    def test(self, init, len_, scapy_checksum):
        inst = SCIONUDPPacket()
        inst._src_addr = create_mock(["pack"])
        inst._src_addr.pack.return_value = b"source address"
        inst._dst_addr = create_mock(["pack"])
        inst._dst_addr.pack.return_value = b"destination address"
        inst.src_port = 0x0042
        inst.dst_port = 0x0302
        inst._payload = b"payload"
        len_.return_value = 0x7
        expected_call = b"".join([
            b"source address",
            b"destination address",
            bytes.fromhex("11 0042 0302 0007"),
            b"payload",
        ])
        # Call
        ntools.eq_(inst._calc_checksum(), scapy_checksum.return_value)
        # Tests
        inst._src_addr.pack.assert_called_once_with()
        inst._dst_addr.pack.assert_called_once_with()
        scapy_checksum.assert_called_once_with(expected_call)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
