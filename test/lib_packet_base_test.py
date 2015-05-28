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
# External packages
import nose.tools as ntools

# SCION
from lib.packet.packet_base import (
    HeaderBase,
    PacketBase,
    PayloadBase
)

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
    def test_bytes(self):
        """
        Test for setting payload as bytes.
        """
        packet_base = PacketBase()
        packet_base.payload = b't9gj646'
        payload = packet_base.payload
        ntools.eq_(payload, b't9gj646')

    def test_packet_base(self):
        """
        Test for setting payload as PacketBase instance.
        """
        payload = PacketBase()
        packet_base = PacketBase()
        packet_base.payload = payload
        ntools.eq_(packet_base.payload, payload)

class TestPacketBaseHdr(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.hdr
    """
    def test_basic(self):
        """
        Test for setting hdr as HeaderBase instance.
        """
        packet_base = PacketBase()
        header = HeaderBase()
        packet_base.hdr = header
        ntools.eq_(packet_base.hdr, header)

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
        payload.parse("rawstring")
        ntools.eq_(payload.raw, "rawstring")

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
