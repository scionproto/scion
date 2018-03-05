# Copyright 2016 ETH Zurich
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
:mod:`lib_packet_scmp_hdr_test` --- lib.packet.scmp.hdr unit tests
==================================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONChecksumFailed
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scmp.hdr import SCMPHeader
from lib.packet.scmp.errors import SCMPBadPktLen
from lib.types import L4Proto
from test.testcommon import create_mock, create_mock_full


class TestSCMPHeaderParse(object):
    """
    Unit tests for lib.packet.scmp.hdr.SCMPHeader._parse
    """
    @patch("lib.packet.scmp.hdr.Raw", autospec=True)
    def test(self, raw):
        inst = SCMPHeader()
        data = create_mock(["pop"])
        data.pop.return_value = bytes.fromhex(
            "11112222000f99992323232323232323")
        raw.return_value = data
        # Call
        inst._parse("src", "dst", "raw")
        # Tests
        raw.assert_called_once_with("raw", inst.NAME, inst.LEN)
        ntools.eq_(inst._src, "src")
        ntools.eq_(inst._dst, "dst")
        ntools.eq_(inst.class_, 0x1111)
        ntools.eq_(inst.type, 0x2222)
        ntools.eq_(inst.total_len, 0x000F)
        ntools.eq_(inst._checksum, bytes.fromhex("9999"))
        ntools.eq_(inst.timestamp, 0x2323232323232323)


class TestSCMPHeaderValidate(object):
    """
    Unit tests for lib.packet.scmp.hdr.SCMPHeader.validate
    """
    @patch("lib.packet.scmp.hdr.Raw", autospec=True)
    def test_bad_length(self, raw):
        inst = SCMPHeader()
        inst.total_len = 10
        # Call
        ntools.assert_raises(SCMPBadPktLen, inst.validate, range(9))

    @patch("lib.packet.scmp.hdr.Raw", autospec=True)
    def test_bad_checksum(self, raw):
        inst = SCMPHeader()
        inst.total_len = 10 + inst.LEN
        inst._calc_checksum = create_mock()
        inst._calc_checksum.return_value = bytes.fromhex("8888")
        inst._checksum = bytes.fromhex("9999")
        # Call
        ntools.assert_raises(SCIONChecksumFailed, inst.validate, range(10))


class TestSCMPHeaderCalcChecksum(object):
    """
    Unit tests for lib.packet.scmp.hdr.SCMPHeader._calc_checksum
    """
    @patch("lib.packet.scmp.hdr.checksum.in_cksum", autospec=True)
    def test(self, in_cksum):
        inst = SCMPHeader()
        src_ia = create_mock_full({"pack()": b"srIA"})
        src_host = create_mock_full({"pack()": b"sHst"})
        inst._src = create_mock_full({"isd_as": src_ia, "host": src_host}, class_=SCIONAddr)
        dst_ia = create_mock_full({"pack()": b"dsIA"})
        dst_host = create_mock_full({"pack()": b"dHst"})
        inst._dst = create_mock_full({"isd_as": dst_ia, "host": dst_host}, class_=SCIONAddr)
        inst.pack = create_mock()
        inst.pack.return_value = b"packed with null checksum"
        payload = b"payload"
        expected_call = b"".join([
            b"dsIA", b"srIA", b"dHst", b"sHst", b"\x00", bytes([L4Proto.SCMP]),
            b"packed with null checksum", payload,
        ])
        in_cksum.return_value = 0x3412
        # Call
        ntools.eq_(inst._calc_checksum(payload), bytes.fromhex("3412"))
        # Tests
        in_cksum.assert_called_once_with(expected_call)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
