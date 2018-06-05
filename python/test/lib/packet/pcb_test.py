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
        ASMarking.from_values(_ISD_AS1, 2, 3, pcbms, "mtu",
                              exts, ifid_size=14)
        # Tests
        p_cls.new_message.assert_called_once_with(
            isdas=_ISD_AS1, trcVer=2, certVer=3, ifIDSize=14, mtu="mtu")
        msg.init.assert_called_once_with("hops", 3)
        for i, pcbm in enumerate(msg.pcbms):
            ntools.eq_("pcbm %d" % i, pcbm)


class TestPathSegmentGetPath(object):
    """
    Unit test for lib.packet.pcb.PathSegment.get_path
    """
    def _setup(self):
        asms = []
        for i in range(3):
            pcbm = create_mock_full({"hof()": "hof %d" % i})
            asms.append(create_mock_full({"pcbm()": pcbm}))
        inst = PathSegment(None)
        inst.iter_asms = create_mock_full(return_value=asms)
        return inst

    @patch("lib.packet.pcb.SCIONPath", autospec=True)
    @patch("lib.packet.pcb.PathSegment.infoF", autospec=True)
    @patch("lib.packet.pcb.PathSegment._setup", autospec=True)
    def test_fwd(self, _, info, scion_path):
        inst = self._setup()
        info.return_value = create_mock_full({"cons_dir_flag": False})
        # Call
        ntools.eq_(inst.get_path(), scion_path.from_values.return_value)
        # Tests
        ntools.eq_(info.return_value.cons_dir_flag, False)
        scion_path.from_values.assert_called_once_with(
            info.return_value, ["hof 0", "hof 1", "hof 2"])

    @patch("lib.packet.pcb.SCIONPath", autospec=True)
    @patch("lib.packet.pcb.PathSegment.infoF", autospec=True)
    @patch("lib.packet.pcb.PathSegment._setup", autospec=True)
    def test_reverse(self, _, info, scion_path):
        inst = self._setup()
        info.return_value = create_mock_full({"cons_dir_flag": False})
        # Call
        ntools.eq_(inst.get_path(True), scion_path.from_values.return_value)
        # Tests
        ntools.eq_(info.return_value.cons_dir_flag, True)
        scion_path.from_values.assert_called_once_with(
            info.return_value, ["hof 2", "hof 1", "hof 0"])


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
