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

# SCIO
from lib.defines import PATH_REQ_TOUT


class RequestState:  # pragma: no cover
    """RequestState stores state about path requests issued by SCIOND to the local PS."""
    def __init__(self, req, checkf):
        self.req = req
        self.reply = None
        self.checkf = checkf
        self._e = threading.Event()
        self._ver_tout = None
        self._segs_to_verify = 0
        self._timeout = threading.Timer(PATH_REQ_TOUT, self._done)
        self._wait = True
        self._timed_out = False
        logging.debug("Start: %s", req.short_desc())

    def wait(self):
        self._e.wait()

    def set_reply(self, reply):
        logging.debug("SetReply: %s", reply.short_desc())
        self.reply = reply
        self._segs_to_verify = self.reply.recs().num_segs()
        self._ver_tout = threading.Timer(0.3, self._ver_tout_fired)
        self._ver_tout.start()

    def verified_segment(self):
        """
        Gets called when a PathSegment of the reply got succesfully verified.
        Immediately try to fulfill a request if self._wait is False. Otherwise,
        wait for more verifications.
        """
        if self._segs_to_verify == 0:
            return
        self._segs_to_verify -= 1
        logging.debug("Verified Segment (%d oustanding): %s",
            self._segs_to_verify, self.req.short_desc())
        if not self._wait:
            self._check()
            return
        # If we have verified all received path segments we can wake up all waiters.
        if self._segs_to_verify == 0:
            self._done()

    def timed_out(self):
        return self._timed_out

    def _check(self):
        """Checks if a request can be fulfilled."""
        if self.checkf(self.req.dst_ia(), self.req.flags()):
            logging.debug("Can fulfill: %s", self.req.short_desc())
            self._done()

    def _ver_tout_fired(self):
        """
        Gets called when the verification timer fired. From now on we try to immediately
        fullfil requests as new path segments get verified.
        """
        logging.debug("Verification Timeout fired for: %s", self.req.short_desc())
        self._wait = False
        self.ver_tout = None
        self._check()

    def _timeout_fired(self):
        logging.debug("Timeout fired for: %s", self.req.short_desc())
        self._timed_out = True
        self._timeout = None
        self._done()

    def _done(self):
        logging.debug("Done: %s", self.req.short_desc())
        # Cancel outstanding timers if there are some.
        if self._ver_tout:
            self._ver_tout.cancel()
            self._ver_tout = None
        if self._timeout:
            self._timeout.cancel()
            self._timeout = None
        self._e.set()
