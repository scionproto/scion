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
from unittest.mock import patch, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.pcb import ASMarking, PCBMarking, PathSegment
from test.testcommon import assert_these_calls, create_mock_full


def mk_pcbm_p(inIF=22):
    return create_mock_full({
        "inIA": "in_ia", "inIF": inIF, "inMTU": 4000, "outIA": "out_ia",
        "outIF": 33, "hof": b"hof", "igRevToken": b"revToken"},
        class_=PCBMarking)


class TestPCBMarkingSigPack(object):
    """
    Unit tests for lib.packet.pcb.PCBMarking.sig_pack
    """
    def test_6(self):
        inst = PCBMarking(mk_pcbm_p())
        expected = b"".join([
            b"in_ia", bytes.fromhex("0000000000000016 0fa0"), b"out_ia",
            bytes.fromhex("0000000000000021"), b"hof", b"revToken"])
        # Call
        ntools.eq_(inst.sig_pack(6), expected)


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
        cchain = create_mock_full({"pack()": "cchain"})
        revs = []
        for i in range(2):
            revs.append(create_mock_full({"pack()": "rev %d" % i}))
        # Call
        ASMarking.from_values("isdas", 2, 3, pcbms, "eg rev token", "mtu",
                              cchain, ifid_size=14, rev_infos=revs)
        # Tests
        p_cls.new_message.assert_called_once_with(
            isdas="isdas", trcVer=2, certVer=3, ifIDSize=14,
            egRevToken="eg rev token", mtu="mtu",
            chain="cchain")
        msg.init.assert_called_once_with("pcbms", 3)
        msg.exts.init.assert_called_once_with("revInfos", 2)
        for i, pcbm in enumerate(msg.pcbms):
            ntools.eq_("pcbm %d" % i, pcbm)
        for i, rev in enumerate(msg.exts.revInfos):
            ntools.eq_("rev %d" % i, rev)


class TestASMarkingSigPack(object):
    """
    Unit tests for lib.packet.pcb.ASMarking.sig_pack
    """
    def test_9(self):
        pcbms = []
        for i in range(3):
            pcbms.append(create_mock_full({
                "sig_pack()": bytes("pcbm %i" % i, "ascii")}))
        exts = create_mock_full({"revInfos": [b"rev0", b"rev1"]})
        inst = ASMarking(create_mock_full({
            "isdas": "isdas", "trcVer": 2, "certVer": 3, "ifIDSize": 4,
            "egRevToken": b"eg rev", "exts": exts, "mtu": 1482, "chain":
            b"chain",
        }))
        inst.iter_pcbms = create_mock_full(return_value=pcbms)
        expected = b"".join([
            b"isdas", bytes.fromhex("00000002 00000003 04"),
            b"pcbm 0", b"pcbm 1", b"pcbm 2", b"eg rev", b"rev0", b"rev1",
            bytes.fromhex("05ca"), b"chain"])
        # Call
        ntools.eq_(inst.sig_pack(9), expected)


class TestPathSegmentSigPack(object):
    """
    Unit tests for lib.packet.pcb.PathSegment.sig_pack
    """
    @patch("lib.packet.pcb.PathSegment._setup", autospec=True)
    def test_3(self, _):
        asms = []
        for i in range(3):
            asms.append(create_mock_full({
                "sig_pack()": bytes("asm %i" % i, "ascii")}))
        inst = PathSegment(create_mock_full({"info": b"info"}))
        inst.is_sibra = create_mock_full()
        inst.iter_asms = create_mock_full(return_value=asms)
        inst.sibra_ext = create_mock_full({"sig_pack()": b"sibraext"})
        expected = b"".join([
            b"info", b"asm 0", b"asm 1", b"asm 2", b"sibraext"])
        # Call
        ntools.eq_(inst.sig_pack(3), expected)


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


class TestPathSegmentGetHopsHash(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_hops_hash
    """
    def _setup(self):
        inst = PathSegment({})
        inst.get_all_iftokens = create_mock_full(return_value=("t0", "t1"))
        h = create_mock_full({'update()': None, 'digest()': "digest",
                              'hexdigest()': "hexdigest"})
        return inst, h

    @patch("lib.packet.pcb.SHA256", autospec=True)
    @patch("lib.packet.pcb.PathSegment._setup", autospec=True)
    def test_basic(self, _, sha):
        inst, h = self._setup()
        sha.new.return_value = h
        # Call
        ntools.eq_(inst.get_hops_hash(), 'digest')
        # Tests
        assert_these_calls(h.update, [call("t0"), call("t1")])

    @patch("lib.packet.pcb.SHA256", autospec=True)
    @patch("lib.packet.pcb.PathSegment._setup", autospec=True)
    def test_hex(self, _, sha):
        inst, h = self._setup()
        sha.new.return_value = h
        # Call
        ntools.eq_(inst.get_hops_hash(hex=True), 'hexdigest')


class TestPathSegmentGetAllIftokens(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_all_iftokens
    """
    @patch("lib.packet.pcb.PathSegment._setup", autospec=True)
    def test(self, _):
        asms = []
        for i in range(3):
            pcbms = []
            for j in range(2):
                pcbms.append(create_mock_full(
                    {"igRevToken": "ig %d %d" % (i, j)}))
            asms.append(create_mock_full({
                "pcbms": pcbms, "egRevToken": "eg %d" % i}))
        inst = PathSegment(create_mock_full({"asms": asms}))
        expected = ['ig 0 0', 'ig 0 1', 'eg 0', 'ig 1 0', 'ig 1 1', 'eg 1',
                    'ig 2 0', 'ig 2 1', 'eg 2']
        # Call
        ntools.eq_(inst.get_all_iftokens(), expected)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
