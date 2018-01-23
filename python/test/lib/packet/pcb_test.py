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
:mod:`lib_packet_pcb_test` --- lib.packet.pcb unit tests
========================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.pcb import ASMarking, PCBMarking, PathSegment
from lib.types import ASMExtType, RoutingPolType
from test.testcommon import create_mock_full

_ISD_AS1 = 1 << 20 | 1
_ISD_AS2 = 1 << 20 | 2
_ISD_AS1_BYTES = _ISD_AS1.to_bytes(4, 'big')
_ISD_AS2_BYTES = _ISD_AS2.to_bytes(4, 'big')


def mk_pcbm_p(remoteInIF=22):
    return create_mock_full({
        "inIA": _ISD_AS1, "remoteInIF": remoteInIF, "inMTU": 4000, "outIA": _ISD_AS2,
        "remoteOutIF": 33, "hof": b"hof"},
        class_=PCBMarking)


class TestPCBMarkingSigPack5(object):
    """
    Unit tests for lib.packet.pcb.PCBMarking.sig_pack5
    """
    def test(self):
        inst = PCBMarking(mk_pcbm_p())
        expected = b"".join([
            _ISD_AS1_BYTES, bytes.fromhex(
                "0000000000000016 0fa0"), _ISD_AS2_BYTES,
            bytes.fromhex("0000000000000021"), b"hof"])
        # Call
        ntools.eq_(inst.sig_pack5(), expected)


class TestASMarkingFromValues(object):
    """
    Unit tests for lib.packet.pcb.ASMarking.from_values
    """
    @patch("lib.packet.pcb.ASMarking.P_CLS", autospec=True)
    def test_full(self, p_cls):
        msg = p_cls.new_message.return_value
        pcbms = []
        for i in range(3):
            pcbms.append(create_mock_full({"p": "pcbm %d" % i}))
        exts = []
        exts.append(create_mock_full({"EXT_TYPE": ASMExtType.ROUTING_POLICY, "p":
                    {"polType": RoutingPolType.ALLOW_AS, "itf": 0, "isdases": [_ISD_AS1]}}))
        # Call
        ASMarking.from_values(_ISD_AS1, 2, 3, pcbms, "root", "mtu",
                              exts, ifid_size=14)
        # Tests
        p_cls.new_message.assert_called_once_with(
            isdas=_ISD_AS1, trcVer=2, certVer=3, ifIDSize=14,
            hashTreeRoot="root", mtu="mtu")
        msg.init.assert_called_once_with("pcbms", 3)
        for i, pcbm in enumerate(msg.pcbms):
            ntools.eq_("pcbm %d" % i, pcbm)


class TestASMarkingSigPack8(object):
    """
    Unit tests for lib.packet.pcb.ASMarking.sig_pack8
    """
    def test(self):
        pcbms = []
        for i in range(3):
            pcbms.append(create_mock_full({
                "sig_pack5()": bytes("pcbm %i" % i, "ascii")}))
        rpe = create_mock_full({"routingPolicy": bytes("exts", "ascii")})
        inst = ASMarking(create_mock_full({
            "isdas": _ISD_AS1, "trcVer": 2, "certVer": 3, "ifIDSize": 4,
            "hashTreeRoot": b"root", "mtu": 1482, "exts": rpe}))
        inst.iter_pcbms = create_mock_full(return_value=pcbms)
        sgp3 = create_mock_full({"sig_pack3()": bytes("exts", "ascii")})
        inst.routing_pol_ext = create_mock_full(return_value=sgp3)
        expected = b"".join([
            _ISD_AS1_BYTES, bytes.fromhex("00000002 00000003 04"),
            b"pcbm 0", b"pcbm 1", b"pcbm 2", b"root",
            bytes.fromhex("05ca"), b"exts"])
        # Call
        ntools.eq_(inst.sig_pack8(), expected)


class TestPathSegmentSigPack3(object):
    """
    Unit tests for lib.packet.pcb.PathSegment.sig_pack3
    """
    @patch("lib.packet.pcb.PathSegment._setup", autospec=True)
    def test(self, _):
        asms = []
        for i in range(3):
            asms.append(create_mock_full({
                "sig_pack8()": bytes("asm %i" % i, "ascii")}))
        inst = PathSegment(create_mock_full({"info": b"info"}))
        inst.is_sibra = create_mock_full()
        inst.iter_asms = create_mock_full(return_value=asms)
        inst.sibra_ext = create_mock_full({"sig_pack3()": b"sibraext"})
        expected = b"".join([
            b"info", b"asm 0", b"asm 1", b"asm 2", b"sibraext"])
        # Call
        ntools.eq_(inst.sig_pack3(), expected)


class TestPathSegmentGetPath(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_path
    """
    def _setup(self):
        asms = []
        for i in range(3):
            pcbm = create_mock_full({"hof()": "hof %d" % i})
            asms.append(create_mock_full({"pcbm()": pcbm}))
        info = create_mock_full({"up_flag": True})
        inst = PathSegment(create_mock_full({"info": info}))
        inst.iter_asms = create_mock_full(return_value=asms)
        return inst

    @patch("lib.packet.pcb.SCIONPath", autospec=True)
    @patch("lib.packet.pcb.InfoOpaqueField", autospec=True)
    @patch("lib.packet.pcb.PathSegment._setup", autospec=True)
    def test_fwd(self, _, info, scion_path):
        inst = self._setup()
        info.side_effect = lambda x: x
        # Call
        ntools.eq_(inst.get_path(), scion_path.from_values.return_value)
        # Tests
        scion_path.from_values.assert_called_once_with(
            inst.p.info, ["hof 0", "hof 1", "hof 2"])

    @patch("lib.packet.pcb.SCIONPath", autospec=True)
    @patch("lib.packet.pcb.InfoOpaqueField", autospec=True)
    @patch("lib.packet.pcb.PathSegment._setup", autospec=True)
    def test_reverse(self, _, info, scion_path):
        inst = self._setup()
        info.side_effect = lambda x: x
        # Call
        ntools.eq_(inst.get_path(True), scion_path.from_values.return_value)
        # Tests
        scion_path.from_values.assert_called_once_with(
            inst.p.info, ["hof 2", "hof 1", "hof 0"])
        ntools.eq_(inst.p.info.up_flag, False)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
