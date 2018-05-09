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
import logging
import threading

# How long to wait (at most) after segments are received before considering the request done.
_WAIT_TIME = 0.2


class RequestState:  # pragma: no cover
    """RequestState stores state about path requests issued by SCIOND to the local PS."""
    def __init__(self, req):
        self.req = req
        self.e = threading.Event()
        self._segs_to_verify = 0
        self._lock = threading.RLock()
        self._timer = threading.Timer(_WAIT_TIME, self.done)
        self._done = False

    def notify_reply(self, reply):
        with self._lock:
            if self._done:
                return
            if self._segs_to_verify > 0:
                logging.error("Received duplicate reply %s", reply)
                return
            self._segs_to_verify = reply.recs().num_segs()
            if self._segs_to_verify > 0:
                self._timer.start()
            else:
                self.done()

    def verified_segment(self):
        """Gets called when a PathSegment of the reply got succesfully verified."""
        with self._lock:
            if self._done:
                return
            self._segs_to_verify -= 1
            if self._segs_to_verify == 0:
                self.done()

    def done(self):
        """Wake up all waiters."""
        with self._lock:
            self._done = True
            self._timer.cancel()
            self.e.set()
