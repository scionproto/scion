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
:mod:`lib_packet_base_test` --- Packet base class tests
=======================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose.tools as ntools

# SCION
from lib.packet.packet_base import (
    HeaderBase,
    PacketBase,
    PayloadBase
)
from lib.packet.ext_hdr import ExtensionHeader


class TestHeaderBaseInit(object):
    """
    Unit tests for lib.packet.packet_base.HeaderBase.__init__
    """
    def test_basic(self):
        """
        Tests proper member initialization.
        """
        header_base = HeaderBase()
        ntools.assert_false(header_base.parsed)


class TestPacketBaseInit(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.__init__
    """
    def test_basic(self):
        """
        Tests proper member initialization.
        """
        packet_base = PacketBase()
        ntools.eq_(packet_base._hdr, None)
        ntools.eq_(packet_base._payload, None)
        ntools.assert_false(packet_base.parsed)
        ntools.eq_(packet_base.raw, None)


class TestPacketBasePayload(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.payload
    """
    def test_getter_bytes(self):
        """
        Test for getting payload as bytes.
        """
        packet_base = PacketBase()
        packet_base._payload = b'data'
        ntools.eq_(packet_base.payload, b'data')

    @patch("lib.packet.packet_base.PacketBase.set_payload")
    def test_setter_bytes(self, set_payload):
        """
        Test for setting payload as bytes.
        """
        packet_base = PacketBase()
        packet_base.payload = b'data'
        set_payload.assert_called_once_with(b'data')

    def test_getter_packet_base(self):
        """
        Test for getting payload as PacketBase instance.
        """
        payload = PacketBase()
        packet_base = PacketBase()
        packet_base._payload = payload
        ntools.eq_(packet_base.payload, payload)

    @patch("lib.packet.packet_base.PacketBase.set_payload")
    def test_setter_packet_base(self, set_payload):
        """
        Test for setting payload as PacketBase instance.
        """
        payload = PacketBase()
        packet_base = PacketBase()
        packet_base.payload = payload
        set_payload.assert_called_once_with(payload)


class TestPacketBaseSetPayload(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.set_payload
    """
    def test_basic(self):
        packet_base = PacketBase()
        payload = PacketBase()
        packet_base.set_payload(payload)
        ntools.eq_(packet_base._payload, payload)
        payload = PayloadBase()
        packet_base.set_payload(payload)
        ntools.eq_(packet_base._payload, payload)
        payload = b'data'
        packet_base.set_payload(payload)
        ntools.eq_(packet_base._payload, payload)
        ntools.assert_raises(TypeError, packet_base.set_payload, 123)
        ntools.assert_raises(TypeError, packet_base.set_payload, '123')
        ntools.assert_raises(TypeError, packet_base.set_payload, 123.4)


class TestPacketBaseHdr(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.hdr
    """
    def test_getter(self):
        packet_base = PacketBase()
        header = HeaderBase()
        packet_base._hdr = header
        ntools.eq_(packet_base.hdr, header)

    @patch("lib.packet.packet_base.PacketBase.set_hdr")
    def test_setter(self, set_hdr):
        packet_base = PacketBase()
        header = HeaderBase()
        packet_base.hdr = header
        set_hdr.assert_called_once_with(header)


class TestPacketBaseSetHdr(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.set_hdr
    """
    def test_basic(self):
        packet_base = PacketBase()
        header = HeaderBase()
        packet_base.set_hdr(header)
        ntools.eq_(packet_base._hdr, header)
        ntools.assert_raises(TypeError, packet_base.set_hdr, 123)
        ntools.assert_raises(TypeError, packet_base.set_hdr, '123')
        ntools.assert_raises(TypeError, packet_base.set_hdr, 123.4)


class TestPacketBaseLen(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.__len__
    """
    def test_basic(self):
        packet_base = PacketBase()
        header = ExtensionHeader(b'data')
        payload = b'data2'
        packet_base.hdr = header
        packet_base.payload = payload
        ntools.eq_(len(packet_base), len(header) + len(payload))


class TestPacketBaseEq(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.__eq__
    """
    def test_basic(self):
        packet_base1 = PacketBase()
        packet_base2 = PacketBase()
        raw = "rawstring"
        packet_base1.raw = raw
        packet_base2.raw = raw
        ntools.eq_(packet_base1, packet_base2)


class TestPayloadBaseInit(object):
    """
    Unit tests for lib.packet.packet_base.PayloadBase.__init__
    """
    def test_basic(self):
        """
        Tests proper member initialization.
        """
        payload = PayloadBase()
        ntools.eq_(payload.raw, None)
        ntools.assert_false(payload.parsed)


class TestPayloadBaseParse(object):
    """
    Unit tests for lib.packet.packet_base.PayloadBase.parse
    """
    def test_basic(self):
        payload = PayloadBase()
        raw = [1,2,3,4]
        payload.parse(raw)
        ntools.eq_(payload.raw, raw)
        ntools.assert_is_not(payload.raw, raw)


class TestPayloadBasePack(object):
    """
    Unit tests for lib.packet.packet_base.PayloadBase.pack
    """
    def test_basic(self):
        payload = PayloadBase()
        payload.parse("rawstring")
        ntools.eq_(payload.pack(), "rawstring")


class TestPayloadBaseLen(object):
    """
    Unit tests for lib.packet.packet_base.PayloadBase.__len__
    """
    def test_basic(self):
        """
        Tests len() on a PayloadBase instance.
        """
        payload = PayloadBase()
        payload.raw = "rawstr"
        ntools.eq_(len(payload), len("rawstr"))

    def test_zero(self):
        """
        Tests len() when `raw` is unset.
        """
        payload = PayloadBase()
        ntools.eq_(len(payload), 0)


class TestPayloadBaseEq(object):
    """
    Unit tests for lib.packet.packet_base.PayloadBase.__eq__
    """
    def test_basic(self):
        """
        Tests equality of two PayloadBase instances.
        """
        payload1 = PayloadBase()
        payload2 = PayloadBase()
        raw = "randomstring"
        payload1.raw = raw
        payload2.raw = raw
        ntools.eq_(payload1, payload2)
