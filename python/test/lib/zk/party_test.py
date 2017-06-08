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
:mod:`party` --- lib.zk.party unit tests
======================================================
"""
# Stdlib
from unittest.mock import MagicMock, patch

# External packages
import nose
import nose.tools as ntools
from kazoo.exceptions import ConnectionLoss, SessionExpiredError

# SCION
from lib.zk.errors import ZkNoConnection
from lib.zk.party import ZkParty
from test.testcommon import create_mock


class TestZkPartyInit(object):
    """
    Unit tests for lib.zk.party.ZkParty.__init__
    """
    @patch("lib.zk.party.ZkParty.autojoin", autospec=True)
    def test_basic(self, autojoin):
        zk = create_mock(["Party"])
        # Call
        p = ZkParty(zk, "path", "id", "autojoin")
        # Tests
        ntools.eq_(p._autojoin, "autojoin")
        ntools.eq_(p._path, "path")
        zk.Party.assert_called_once_with("path", "id")
        ntools.eq_(p._party, zk.Party.return_value)
        autojoin.assert_called_once_with(p)

    @patch("lib.zk.party.ZkParty.autojoin", autospec=True)
    def _check_error(self, excp, autojoin):
        zk = create_mock(["Party"])
        zk.Party.side_effect = excp
        # Call
        ntools.assert_raises(ZkNoConnection, ZkParty, zk, "path",
                             "id", True)

    def test_error(self):
        for excp in ConnectionLoss, SessionExpiredError:
            yield self._check_error, excp


class TestZkPartyJoin(object):
    """
    Unit tests for lib.zk.party.ZkParty.join
    """
    @patch("lib.zk.party.ZkParty.__init__", autospec=True, return_value=None)
    def test_basic(self, init):
        p = ZkParty("zk", "path", "id", "autojoin")
        p._party = create_mock(["join"])
        p.list = create_mock()
        # Call
        p.join()
        # Tests
        p._party.join.assert_called_once_with()

    @patch("lib.zk.party.ZkParty.__init__", autospec=True, return_value=None)
    def _check_error(self, excp, init):
        p = ZkParty("zk", "path", "id", "autojoin")
        p._party = create_mock(["join"])
        p._party.join.side_effect = excp
        # Call
        ntools.assert_raises(ZkNoConnection, p.join)

    def test_error(self):
        for excp in ConnectionLoss, SessionExpiredError:
            yield self._check_error, excp


class TestZkPartyAutoJoin(object):
    """
    Unit tests for lib.zk.party.ZkParty.autojoin
    """
    @patch("lib.zk.party.ZkParty.list", autospec=True)
    @patch("lib.zk.party.ZkParty.__init__", autospec=True, return_value=None)
    def test_auto(self, init, list_):
        p = ZkParty("zk", "path", "id", "autojoin")
        p._autojoin = True
        p.join = create_mock()
        p._path = "path"
        # Call
        p.autojoin()
        # Tests
        p.join.assert_called_once_with()

    @patch("lib.zk.party.ZkParty.list", autospec=True)
    @patch("lib.zk.party.ZkParty.__init__", autospec=True, return_value=None)
    def test_noauto(self, init, list_):
        p = ZkParty("zk", "path", "id", "autojoin")
        p._autojoin = False
        p.join = create_mock()
        p._path = "path"
        # Call
        p.autojoin()
        # Tests
        ntools.assert_false(p.join.called)


class TestZkPartyList(object):
    """
    Unit tests for lib.zk.party.ZkParty.list
    """
    @patch("lib.zk.party.ZkParty.__init__", autospec=True, return_value=None)
    def test_basic(self, init):
        p = ZkParty("zk", "path", "id", "autojoin")
        p._party = MagicMock(spec_set=["__iter__"])
        p._party.__iter__.return_value = [1, 2, 3]
        # Call
        ntools.eq_(p.list(), {1, 2, 3})

    @patch("lib.zk.party.ZkParty.__init__", autospec=True, return_value=None)
    def _check_error(self, excp, init):
        p = ZkParty("zk", "path", "id", "autojoin")
        p._party = create_mock(["__iter__"])
        p._party.__iter__.side_effect = excp
        # Call
        ntools.assert_raises(ZkNoConnection, p.list)

    def test_error(self):
        for excp in ConnectionLoss, SessionExpiredError:
            yield self._check_error, excp


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
