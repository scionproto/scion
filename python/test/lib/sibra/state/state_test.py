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


class TestSibraStateUpdateTick(object):
    """
    Unit tests for lib.sibra.state.state.SibraState.update_tick
    """
    @patch("lib.sibra.state.state.current_tick", autospec=True)
    @patch("lib.sibra.state.state.LinkBandwidth", autospec=True)
    def test(self, _, curr_tick):
        inst = SibraState("bw", "isd as")
        inst.curr_tick = 0
        inst.link = create_mock(["next"])
        inst.steady = "steady"
        inst.ephemeral = "ephemeral"
        inst._resv_tick = create_mock()
        curr_tick.return_value = 3
        # Call
        inst.update_tick()
        # Tests
        ntools.eq_(inst.curr_tick, 3)
        assert_these_calls(inst.link.next, [call()] * 3)
        assert_these_calls(inst._resv_tick,
                           [call("steady"), call("ephemeral")] * 3)


class TestSibraStateResvTick(object):
    """
    Unit tests for lib.sibra.state.state.SibraState._resv_tick
    """
    @patch("lib.sibra.state.state.LinkBandwidth", autospec=True)
    def test(self, _):
        inst = SibraState("bw", "isd as")
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


class TestSibraStateAddSteady(object):
    """
    Unit tests for lib.sibra.state.state.SibraState.add_steady
    """
    @patch("lib.sibra.state.state.LinkBandwidth", autospec=True)
    def test_setup_success(self, _):
        inst = SibraState("bw", "isd as")
        inst.update_tick = create_mock()
        inst._create_steady = create_mock()
        inst._create_steady.return_value = "resv"
        inst._add = create_mock()
        inst._add.return_value = None
        # Call
        inst.add_steady("path id", "resv idx", "bwsnap", "exp_tick", "accepted")
        # Tests
        inst.update_tick.assert_called_once_with()
        inst._create_steady.assert_called_once_with("path id")
        inst._add.assert_called_once_with(
            "resv", "resv idx", "bwsnap", "exp_tick", "accepted")
        ntools.eq_(inst.steady, {"path id": "resv"})
        ntools.eq_(inst.pend_steady, {"path id": True})

    @patch("lib.sibra.state.state.LinkBandwidth", autospec=True)
    def test_renewal_denied(self, _):
        inst = SibraState("bw", "isd as")
        inst.update_tick = create_mock()
        inst._add = create_mock()
        inst.steady["path id"] = "resv"
        # Call
        ntools.eq_(
            inst.add_steady("path id", "resv idx", "bwsnap", "exp_tick",
                            "accepted", setup=False),
            inst._add.return_value)
        # Tests
        inst._add.assert_called_once_with(
            "resv", "resv idx", "bwsnap", "exp_tick", "accepted")


class TestSibraStateAddEphemeral(object):
    """
    Unit tests for lib.sibra.state.state.SibraState.add_ephemeral
    """
    @patch("lib.sibra.state.state.LinkBandwidth", autospec=True)
    def test_setup_success(self, _):
        inst = SibraState("bw", "isd as")
        inst.update_tick = create_mock()
        inst._create_ephemeral = create_mock()
        inst._create_ephemeral.return_value = "resv"
        inst._add = create_mock()
        inst._add.return_value = None
        inst.steady["steady id"] = create_mock(["add_child"])
        # Call
        inst.add_ephemeral("path id", "steady id", "resv idx", "bwsnap",
                           "exp_tick", "accepted")
        # Tests
        inst.update_tick.assert_called_once_with()
        inst._create_ephemeral.assert_called_once_with("path id", "steady id")
        inst._add.assert_called_once_with(
            "resv", "resv idx", "bwsnap", "exp_tick", "accepted")
        ntools.eq_(inst.ephemeral, {"path id": "resv"})
        ntools.eq_(inst.pend_ephemeral, {"path id": True})
        inst.steady["steady id"].add_child.assert_called_once_with("path id")

    @patch("lib.sibra.state.state.LinkBandwidth", autospec=True)
    def test_renewal_denied(self, _):
        inst = SibraState("bw", "isd as")
        inst.update_tick = create_mock()
        inst._add = create_mock()
        inst.ephemeral["path id"] = "resv"
        # Call
        ntools.eq_(
            inst.add_ephemeral("path id", "steady id", "resv idx", "bwsnap",
                               "exp_tick", "accepted", setup=False),
            inst._add.return_value)
        # Tests
        inst._add.assert_called_once_with(
            "resv", "resv idx", "bwsnap", "exp_tick", "accepted")


class TestSibraStateAdd(object):
    """
    Unit tests for lib.sibra.state.state.SibraState._add
    """
    @patch("lib.sibra.state.state.LinkBandwidth", autospec=True)
    def test_full(self, _):
        inst = SibraState("bw", "isd as")
        inst.curr_tick = "curr tick"
        resv = create_mock(["add"])
        bwhint_cls = create_mock(["floor"])
        bwhint = create_mock(["to_classes"])
        bwhint.to_classes.return_value = bwhint_cls
        resv.add.return_value = bwhint
        # Call
        ntools.eq_(inst._add(resv, "resv idx", "bwsnap", "exp_tick", False),
                   bwhint_cls.floor.return_value)
        # Tests
        resv.add.assert_called_once_with("resv idx", "bwsnap", "exp_tick",
                                         "curr tick")
        bwhint.to_classes.assert_called_once_with(floor=True)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
