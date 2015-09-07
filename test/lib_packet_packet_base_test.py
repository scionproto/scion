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
import nose
import nose.tools as ntools

# SCION
from lib.packet.packet_base import (
    HeaderBase,
    PacketBase,
    PayloadBase
)
from test.testcommon import create_mock


# To allow testing of HeaderBase, despite it having abstract methods.
class HeaderBaseTesting(HeaderBase):
    def parse(self):
        pass

    def pack(self):
        pass

    def __len__(self):
        pass

    def __str__(self):
        pass


# To allow testing of PacketBase, despite it having abstract methods.
class PacketBaseTesting(PacketBase):
    def parse(self):
        pass

    def pack(self):
        pass


class TestHeaderBaseInit(object):
    """
    Unit tests for lib.packet.packet_base.HeaderBase.__init__
    """
    def test_basic(self):
        """
        Tests proper member initialization.
        """
        header_base = HeaderBaseTesting()
        ntools.assert_false(header_base.parsed)


class TestPacketBaseInit(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.__init__
    """
    def test_basic(self):
        """
        Tests proper member initialization.
        """
        packet_base = PacketBaseTesting()
        ntools.assert_is_none(packet_base.hdr)
        ntools.assert_is_none(packet_base._payload)
        ntools.assert_false(packet_base.parsed)
        ntools.assert_is_none(packet_base.raw)


class TestPacketBaseGetPayload(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.get_payload
    """
    def test(self):
        """
        Test for getting payload as bytes.
        """
        packet_base = PacketBaseTesting()
        packet_base._payload = b'data'
        ntools.eq_(packet_base.get_payload(), b'data')


class TestPacketBaseSetPayload(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.set_payload
    """
    def check_success(self, payload):
        # Setup
        packet_base = PacketBaseTesting()
        # Call
        packet_base.set_payload(payload)
        # Tests
        ntools.eq_(packet_base._payload, payload)

    def test_success(self):
        for i in PacketBaseTesting(), PayloadBase(), b'test':
            yield self.check_success, i

    def test_failure(self):
        packet_base = PacketBaseTesting()
        ntools.assert_raises(TypeError, packet_base.set_payload, 123)


class TestPacketBaseLen(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.__len__
    """
    def test_basic(self):
        packet_base = PacketBaseTesting()
        header = b'data1'
        payload = b'data2'
        packet_base.hdr = header
        packet_base._payload = payload
        ntools.eq_(len(packet_base), len(header) + len(payload))


class TestPacketBaseHash(object):
    """
    Unit tests for lib.packet.packet_base.PacketBase.__hash__
    """
    def test(self):
        packet_base = PacketBaseTesting()
        pack = create_mock()
        pack.return_value = create_mock(['__hash__'])
        pack.return_value.__hash__.return_value = 123
        packet_base.pack = pack
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
        packet_base1 = PacketBaseTesting()
        packet_base2 = PacketBaseTesting()
        raw = "rawstring"
        packet_base1.raw = raw
        packet_base2.raw = raw
        ntools.eq_(packet_base1, packet_base2)

    def test_neq(self):
        """
        Tests comparison with object of same type, but different raw values
        """
        packet_base1 = PacketBaseTesting()
        packet_base2 = PacketBaseTesting()
        packet_base1.raw = 'raw1'
        packet_base2.raw = 'raw2'
        ntools.assert_not_equals(packet_base1, packet_base2)

    def test_type_neq(self):
        """
        Tests comparison with an object not of the same type
        """
        packet_base1 = PacketBaseTesting()
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
        raw = b"asdf"
        payload.parse(raw)
        ntools.eq_(payload.raw, raw)


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
        payload.raw = create_mock(['__hash__'])
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
