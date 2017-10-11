# Copyright 2017 ETH Zurich
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

# Stdlib
import threading

# SCIO
from lib.defines import PATH_REQ_TOUT

_WAIT_TIME = 0.5


class RequestState:  # pragma: no cover
    """RequestState stores state about path requests issued by SCIOND to the local PS."""
    def __init__(self, req, checkf):
        self.req = req
        self.reply = None
        self.checkf = checkf
        self._e = threading.Event()
        self._segs_to_verify = 0
        self._wait = True
        self._timed_out = False
        self._lock = threading.Lock()
        self._timer = threading.Timer(_WAIT_TIME, self._first_timer_fired)
        self._timer.start()

    def wait(self):
        self._e.wait()

    def set_reply(self, reply):
        with self._lock:
            self.reply = reply
            self._segs_to_verify = self.reply.recs().num_segs()

    def verified_segment(self):
        """
        Gets called when a PathSegment of the reply got succesfully verified.
        Immediately try to fulfill a request if self._wait is False. Otherwise,
        wait for more verifications.
        """
        with self._lock:
            if self._segs_to_verify == 0:
                return
            self._segs_to_verify -= 1
            if not self._wait:
                self._check()
                return
            # If we have verified all received path segments we can wake up all waiters.
            if self._segs_to_verify == 0:
                self._done()

    def timed_out(self):
        with self._lock:
            return self._timed_out

    def _first_timer_fired(self):
        """
        Gets called when the first timer fired. From now on we try to immediately
        fulfill requests as new path segments get verified.
        """
        with self._lock:
            self._wait = False
            if not self._check():
                self._timer = threading.Timer(PATH_REQ_TOUT - _WAIT_TIME, self._second_timer_fired)
                self._timer.start()

    def _second_timer_fired(self):
        """
        Gets called when the second timer fired. Wake up all waiters and do not
        bother waiting any longer for a reply or verifications.
        """
        with self._lock:
            self._timed_out = True
            self._timer = None
            self._done()

    def _check(self):
        """Checks if a request can be fulfilled."""
        if self.checkf(self.req.dst_ia(), self.req.flags()):
            self._done()
            return True
        return False

    def _done(self):
        """Wake up all waiters."""
        # Cancel outstanding timer if there is one.
        if self._timer:
            self._timer.cancel()
            self._timer = None
        self._e.set()
