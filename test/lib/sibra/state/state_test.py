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
:mod:`state_test` --- lib.sibra.state.state unit tests
======================================================
"""
# Stdlib
from unittest.mock import patch, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.sibra.state.state import SibraState
from test.testcommon import assert_these_calls, create_mock


class TestSibraStateInit(object):
    """
    Unit tests for lib.sibra.state.state.SibraState.__init__
    """
    @patch("lib.sibra.state.state.LinkBandwidth", autospec=True)
    @patch("lib.sibra.state.state.BWSnapshot", autospec=True)
    @patch("lib.sibra.state.state.current_tick", autospec=True)
    def test(self, curr_tick, bwsnap, linkbw):
        # Call
        inst = SibraState(2, "isd ad")
        # Tests
        ntools.eq_(inst.curr_tick, curr_tick.return_value)
        bwsnap.assert_called_once_with(2048, 2048)
        linkbw.assert_called_once_with("isd ad", bwsnap.return_value)
        ntools.eq_(inst.link, linkbw.return_value)


class TestSibraStateUpdateTick(object):
    """
    Unit tests for lib.sibra.state.state.SibraState._update_tick
    """
    @patch("lib.sibra.state.state.current_tick", autospec=True)
    @patch("lib.sibra.state.state.SibraState.__init__",
           autospec=True, return_value=None)
    def test(self, init, curr_tick):
        inst = SibraState("bw", "isd ad")
        inst.curr_tick = 0
        inst.link = create_mock(["next"])
        inst.steady = "steady"
        inst.ephemeral = "ephemeral"
        inst._resv_tick = create_mock()
        curr_tick.return_value = 3
        # Call
        inst._update_tick()
        # Tests
        ntools.eq_(inst.curr_tick, 3)
        assert_these_calls(inst.link.next, [call()] * 3)
        assert_these_calls(inst._resv_tick,
                           [call("steady"), call("ephemeral")] * 3)


class TestSibraStateResvTick(object):
    """
    Unit tests for lib.sibra.state.state.SibraState._resv_tick
    """
    @patch("lib.sibra.state.state.SibraState.__init__",
           autospec=True, return_value=None)
    def test(self, init):
        inst = SibraState("bw", "isd ad")
        inst.curr_tick = "curr tick"
        resvs = []
        for i in range(4):
            resv = create_mock(["next"])
            resv.next.return_value = bool(i % 2)
            resvs.append(resv)
        resv_dict = dict(enumerate(resvs))
        # Calls
        inst._resv_tick(resv_dict)
        # Tests
        for resv in resvs:
            resv.next.assert_called_once_with("curr tick")
        ntools.eq_(resv_dict, {1: resvs[1], 3: resvs[3]})


class TestSibraStateSteadyAdd(object):
    """
    Unit tests for lib.sibra.state.state.SibraState.steady_add
    """
    @patch("lib.sibra.state.state.SteadyReservation", autospec=True)
    @patch("lib.sibra.state.state.ISD_AD", autospec=True)
    @patch("lib.sibra.state.state.SibraState.__init__",
           autospec=True, return_value=None)
    def test_setup_accepted_success(self, init, isd_ad, st_resv):
        inst = SibraState("bw", "isd ad")
        inst._update_tick = create_mock()
        inst.steady = {}
        inst.pend_steady = {}
        inst.link = "link"
        inst.curr_tick = 42
        resv = create_mock(["add"])
        resv.add.return_value = "bwsnap"
        st_resv.return_value = resv
        isd_ad.LEN = 100
        # Call
        ntools.assert_is_none(inst.steady_add(
            "path id", "resv idx", "bwsnap", 50, True, setup=True))
        # Tests
        isd_ad.from_raw.assert_called_once_with("path id")
        st_resv.assert_called_once_with(
            "path id", isd_ad.from_raw.return_value, "link")
        resv.add.assert_called_once_with("resv idx", "bwsnap", 50, 42)
        ntools.eq_(inst.steady, {"path id": resv})
        ntools.eq_(inst.pend_steady, {"path id": True})

    @patch("lib.sibra.state.state.SibraState.__init__",
           autospec=True, return_value=None)
    def _check_denied(self, accepted, init):
        inst = SibraState("bw", "isd ad")
        inst._update_tick = create_mock()
        inst.curr_tick = 42
        resv = create_mock(["add"])
        bwhint_cls = create_mock(["floor"])
        bwhint = create_mock(["to_classes"])
        bwhint.to_classes.return_value = bwhint_cls
        resv.add.return_value = bwhint
        inst.steady = {"path id": resv}
        # Call
        ntools.eq_(inst.steady_add("path id", "resv idx", "bwsnap", 50,
                                   True, setup=False),
                   bwhint_cls.floor.return_value)

    def test_renew_denied(self):
        yield self._check_denied, True
        yield self._check_denied, False

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
