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
from unittest.mock import call, patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.defines import LINE_LEN
from lib.packet.scmp.payload import SCMPPayload
from lib.packet.scmp.types import SCMPIncParts
from lib.types import L4Proto
from test.testcommon import assert_these_calls, create_mock


class TestSCMPPayloadParse(object):
    """
    Unit tests for lib.packet.scmp.payload.SCMPPayload._parse
    """
    @patch("lib.packet.scmp.payload.parse_scmp_info", autospec=True)
    @patch("lib.packet.scmp.payload.Raw", autospec=True)
    def test(self, raw, scmp_info):
        inst = SCMPPayload()
        data = create_mock(["pop"])
        data.pop.side_effect = (
            bytes.fromhex("0102030405060700"),
            "info", "cmn hdr", "addrs", "path", "exts", "l4 hdr",
        )
        raw.return_value = data
        # Call
        inst._parse("class", "type", "data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME)
        ntools.eq_(inst.l4_proto, 0x07)
        pop_calls = [call(inst.META_LEN)] + [
            call(x * LINE_LEN) for x in range(1, 7)]
        assert_these_calls(data.pop, pop_calls)
        scmp_info.assert_called_once_with("class", "type", "info")
        ntools.eq_(inst.info, scmp_info.return_value)
        ntools.eq_(inst._cmn_hdr, "cmn hdr")
        ntools.eq_(inst._addrs, "addrs")
        ntools.eq_(inst._path, "path")
        ntools.eq_(inst._exts, "exts")
        ntools.eq_(inst._l4_hdr, "l4 hdr")


class TestSCMPPayloadFromPkt(object):
    """
    Unit tests for lib.packet.scmp.payload.SCMPPayload.from_pkt
    """
    @patch("lib.packet.scmp.payload.scmp_get_inc_parts", autospec=True)
    @patch("lib.packet.scmp.payload.build_scmp_info", autospec=True)
    def _setup(self, inc_list, build_info, inc_parts):
        pkt = create_mock(["cmn_hdr", "addrs", "path", "pack_exts", "l4_hdr"])
        pkt.cmn_hdr = create_mock(["pack"])
        pkt.addrs = create_mock(["pack"])
        pkt.path = create_mock(["pack"])
        pkt.pack_exts = create_mock()
        pkt.l4_hdr = create_mock(["TYPE", "pack"])
        inc_parts.return_value = inc_list
        # Call
        inst = SCMPPayload.from_pkt("class", "type", pkt, "arg1", "arg2",
                                    kwarg1="kwval1")
        # Tests
        build_info.assert_called_once_with("class", "type", pkt, "arg1",
                                           "arg2", kwarg1="kwval1")
        ntools.eq_(inst.info, build_info.return_value)
        inc_parts.assert_called_once_with("class", "type")
        return inst, pkt

    def test_min(self):
        inst, pkt = self._setup([])
        ntools.eq_(inst._cmn_hdr, b"")
        ntools.eq_(inst._addrs, b"")
        ntools.eq_(inst._path, b"")
        ntools.eq_(inst._exts, b"")
        ntools.eq_(inst._l4_hdr, b"")
        ntools.eq_(inst.l4_proto, L4Proto.NONE)

    def test_full(self):
        inst, pkt = self._setup(
            [SCMPIncParts.CMN, SCMPIncParts.ADDRS, SCMPIncParts.PATH,
             SCMPIncParts.EXTS, SCMPIncParts.L4])
        ntools.eq_(inst._cmn_hdr, pkt.cmn_hdr.pack.return_value)
        ntools.eq_(inst._addrs, pkt.addrs.pack.return_value)
        ntools.eq_(inst._path, pkt.path.pack.return_value)
        ntools.eq_(inst._exts, pkt.pack_exts.return_value)
        ntools.eq_(inst._l4_hdr, pkt.l4_hdr.pack.return_value)
        ntools.eq_(inst.l4_proto, pkt.l4_hdr.TYPE)


class TestSCMPPayloadPack(object):
    """
    Unit tests for lib.packet.scmp.payload.SCMPPayload.pack
    """
    def _setup(self):
        inst = SCMPPayload()
        inst._pack_meta = create_mock()
        inst._pack_meta.return_value = b"metadata"
        return inst

    def test_min(self):
        inst = self._setup()
        # Call
        ntools.eq_(inst.pack(), b"metadata")

    def test_full(self):
        inst = self._setup()
        inst.info = create_mock(["__len__", "pack"])
        inst.info.__len__.return_value = 8
        inst.info.pack.return_value = b"info hdr"
        inst._cmn_hdr = b"cmn hdr "
        inst._addrs = b"addr hdr"
        inst._path = b"path hdr"
        inst._exts = b"ext hdrs"
        inst._l4_hdr = b"l4 proto header "
        expected = (b"metadata" b"info hdr" b"cmn hdr " b"addr hdr" b"path hdr"
                    b"ext hdrs" b"l4 proto header ")
        # Call
        ntools.eq_(inst.pack(), expected)


class TestSCMPPayloadPackMeta(object):
    """
    Unit tests for lib.packet.scmp.payload.SCMPPayload._pack_meta
    """
    def _setup(self):
        inst = SCMPPayload()
        inst._cmn_hdr = b"cmn hdr "
        inst._addrs = b"addr hdr"
        inst._path = b"path hdr"
        inst._exts = b"ext hdrs"
        inst._l4_hdr = b"l4 proto header "
        inst.l4_proto = 42
        return inst

    def test_with_info(self):
        inst = self._setup()
        inst.info = create_mock(["__len__"])
        inst.info.__len__.return_value = 32
        # Call
        ntools.eq_(inst._pack_meta(), bytes([4, 1, 1, 1, 1, 2, 42, 0]))

    def test_no_info(self):
        inst = self._setup()
        # Call
        ntools.eq_(inst._pack_meta(), bytes([0, 1, 1, 1, 1, 2, 42, 0]))


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
