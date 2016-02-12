# Copyright 2014 ETH Zurich
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
:mod:`if_state` --- Interface state handling
============================================
"""
# Stdlib
import threading

# SCION
from lib.defines import IFID_PKT_TOUT
from lib.util import SCIONTime


class InterfaceState(object):
    """
    Simple class that represents current state of an interface.
    """
    # Timeout for interface (link) status.
    IFID_TOUT = 10 * IFID_PKT_TOUT

    INACTIVE = 0
    ACTIVE = 1
    TIMED_OUT = 2
    REVOKED = 3

    def __init__(self):
        self.active_since = 0
        self.last_updated = 0
        self._state = self.INACTIVE
        self._lock = threading.RLock()

    def update(self):
        """
        Updates the state of the object.

        :returns: The previous state
        :rtype: int
        """
        with self._lock:
            curr_time = SCIONTime.get_time()
            prev_state = self._state
            if self._state != self.ACTIVE:
                self.active_since = curr_time
                self._state = self.ACTIVE
            self.last_updated = curr_time
            return prev_state

    def reset(self):
        """
        Resets the state of an InterfaceState object.
        """
        with self._lock:
            self.active_since = 0
            self.last_updated = 0
            self._state = self.INACTIVE

    def revoke_if_expired(self):
        """
        Sets the state of the interface to revoked.
        """
        with self._lock:
            if self._state == self.TIMED_OUT:
                self._state = self.REVOKED

    def is_inactive(self):
        return self._state == self.INACTIVE

    def is_active(self):
        with self._lock:
            if self._state == self.ACTIVE:
                if self.last_updated + self.IFID_TOUT >= SCIONTime.get_time():
                    return True
                self._state = self.TIMED_OUT
                return False
            return False

    def is_expired(self):
        with self._lock:
            if self._state == self.TIMED_OUT:
                return True
            elif (self._state == self.ACTIVE and
                  self.last_updated + self.IFID_TOUT < SCIONTime.get_time()):
                self._state = self.TIMED_OUT
                return True
            return False

    def is_revoked(self):
        return self._state == self.REVOKED
