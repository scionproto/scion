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
from unittest.mock import patch, MagicMock

# External packages
import nose
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
        ntools.assert_is_none(packet_base._hdr)
        ntools.assert_is_none(packet_base._payload)
        ntools.assert_false(packet_base.parsed)
        ntools.assert_is_none(packet_base.raw)


class TestPacketBasePayload(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.payload
    """
    def test_getter(self):
        """
        Test for getting payload as bytes.
        """
        packet_base = PacketBase()
        packet_base._payload = b'data'
        ntools.eq_(packet_base.payload, b'data')

    @patch("lib.packet.packet_base.PacketBase.set_payload", autospec=True)
    def test_setter(self, set_payload):
        """
        Test for setting payload as bytes.
        """
        packet_base = PacketBase()
        packet_base.payload = b'data'
        set_payload.assert_called_once_with(packet_base, b'data')


class TestPacketBaseSetPayload(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.set_payload
    """
    def check_success(self, payload):
        # Setup
        packet_base = PacketBase()
        # Call
        packet_base.set_payload(payload)
        # Tests
        ntools.eq_(packet_base._payload, payload)

    def test_success(self):
        for i in PacketBase(), PayloadBase(), b'test':
            yield self.check_success, i

    def test_failure(self):
        packet_base = PacketBase()
        ntools.assert_raises(TypeError, packet_base.set_payload, 123)


class TestPacketBaseHdr(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.hdr
    """
    def test_getter(self):
        packet_base = PacketBase()
        packet_base._hdr = 'data'
        ntools.eq_(packet_base.hdr, 'data')

    @patch("lib.packet.packet_base.PacketBase.set_hdr", autospec=True)
    def test_setter(self, set_hdr):
        packet_base = PacketBase()
        packet_base.hdr = 'data'
        set_hdr.assert_called_once_with(packet_base, 'data')


class TestPacketBaseSetHdr(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.set_hdr
    """
    def test_success(self):
        """
        Tests set_hdr when called with correct argument type
        """
        packet_base = PacketBase()
        header = HeaderBase()
        packet_base.set_hdr(header)
        ntools.eq_(packet_base._hdr, header)

    def test_failure(self):
        """
        Tests set_hdr with incorrect argument type
        """
        packet_base = PacketBase()
        ntools.assert_raises(TypeError, packet_base.set_hdr, '123')


class TestPacketBaseLen(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.__len__
    """
    def test_basic(self):
        packet_base = PacketBase()
        header = b'data1'
        payload = b'data2'
        packet_base._hdr = header
        packet_base._payload = payload
        ntools.eq_(len(packet_base), len(header) + len(payload))


class TestPacketBaseHash(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.__hash__
    """
    @patch("lib.packet.packet_base.PacketBase.pack", autospec=True)
    def test(self, pack):
        packet_base = PacketBase()
        pack.return_value = MagicMock(spec_set=['__hash__'])
        pack.return_value.__hash__.return_value = 123
        ntools.eq_(hash(packet_base), 123)
        pack.return_value.__hash__.assert_called_once_with()


class TestPacketBaseEq(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.__eq__
    """
    def test_eq(self):
        """
        Tests comparison with object of same type, same raw values
        """
        packet_base1 = PacketBase()
        packet_base2 = PacketBase()
        raw = "rawstring"
        packet_base1.raw = raw
        packet_base2.raw = raw
        ntools.eq_(packet_base1, packet_base2)

    def test_neq(self):
        """
        Tests comparison with object of same type, but different raw values
        """
        packet_base1 = PacketBase()
        packet_base2 = PacketBase()
        packet_base1.raw = 'raw1'
        packet_base2.raw = 'raw2'
        ntools.assert_not_equals(packet_base1, packet_base2)

    def test_type_neq(self):
        """
        Tests comparison with an object not of the same type
        """
        packet_base1 = PacketBase()
        packet_base2 = b'test'
        ntools.assert_not_equals(packet_base1, packet_base2)


class TestPayloadBaseInit(object):
    """
    Unit tests for lib.packet.packet_base.PayloadBase.__init__
    """
    def test_basic(self):
        """
        Tests proper member initialization.
        """
        payload = PayloadBase()
        ntools.assert_is_none(payload.raw)
        ntools.assert_false(payload.parsed)


class TestPayloadBaseParse(object):
    """
    Unit tests for lib.packet.packet_base.PayloadBase.parse
    """
    def test_basic(self):
        payload = PayloadBase()
        raw = [1, 2, 3, 4]
        payload.parse(raw)
        ntools.eq_(payload.raw, raw)
        ntools.assert_is_not(payload.raw, raw)


class TestPayloadBasePack(object):
    """
    Unit tests for lib.packet.packet_base.PayloadBase.pack
    """
    def test_basic(self):
        payload = PayloadBase()
        payload.raw = "rawstring"
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


class TestPayloadBaseHash(object):
    """
    Unit tests for lib.packet.packet_base.PayloadBase.__hash__
    """
    def test(self):
        payload = PayloadBase()
        payload.raw = MagicMock(spec_set=['__hash__'])
        payload.raw.__hash__.return_value = 123
        ntools.eq_(hash(payload), 123)
        payload.raw.__hash__.assert_called_once_with()


class TestPayloadBaseEq(object):
    """
    Unit tests for lib.packet.packet_base.PayloadBase.__eq__
    """
    def test_eq(self):
        """
        Tests comparison with object of same type, same raw values
        """
        payload1 = PayloadBase()
        payload2 = PayloadBase()
        raw = "randomstring"
        payload1.raw = raw
        payload2.raw = raw
        ntools.eq_(payload1, payload2)

    def test_neq(self):
        """
        Tests comparison with object of same type, but different raw values
        """
        payload1 = PayloadBase()
        payload2 = PayloadBase()
        payload1.raw = 'raw1'
        payload2.raw = 'raw2'
        ntools.assert_not_equals(payload1, payload2)

    def test_type_neq(self):
        """
        Tests comparison with an object not of the same type
        """
        payload1 = PayloadBase()
        payload2 = b'test'
        ntools.assert_not_equals(payload1, payload2)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
