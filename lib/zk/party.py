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
:mod:`party` --- Zookeeper party
================================
"""
# Stdlib
import logging
from base64 import b64decode

# External packages
from kazoo.exceptions import ConnectionLoss, SessionExpiredError

# SCION
from lib.zk.errors import ZkNoConnection
from lib.zk.id import ZkID


class ZkParty(object):
    """
    A wrapper for a `Kazoo Party
    <https://kazoo.readthedocs.org/en/latest/api/recipe/party.html>`_.
    """
    def __init__(self, zk, path, id_, autojoin_):
        """
        :param zk: A kazoo instance
        :param str path: The absolute path of the party
        :param str id_: The service id value to use in the party
        :param bool autojoin_: Join the party automatically
        :raises:
            ZkNoConnection: if there's no connection to ZK.
        """
        self._autojoin = autojoin_
        self._path = path
        try:
            self._party = zk.Party(path, id_)
        except (ConnectionLoss, SessionExpiredError):
            raise ZkNoConnection from None
        self.autojoin()

    def join(self):
        """
        Join Kazoo Party.

        :raises:
            ZkNoConnection: if there's no connection to ZK.
        """
        try:
            self._party.join()
        except (ConnectionLoss, SessionExpiredError):
            raise ZkNoConnection from None

    def autojoin(self):
        """If the autojoin parameter was set to True, join the party."""
        if self._autojoin:
            self.join()
        entries = []
        for e in self.list():
            raw = b64decode(e)
            entries.append(ZkID.from_raw(raw))
        logging.debug("Current party (%s) members are: %s", self._path,
                      [str(e) for e in entries])

    def list(self):
        """
        List the current party member IDs

        :raises:
            ZkNoConnection: if there's no connection to ZK.
        """
        try:
            return set(self._party)
        except (ConnectionLoss, SessionExpiredError):
            raise ZkNoConnection from None
