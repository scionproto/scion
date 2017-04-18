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
:mod:`requests` --- Request handling library
============================================
"""
# Stdlib
import logging
import threading
import queue
from collections import defaultdict

# SCION
from lib.thread import thread_safety_net
from lib.util import SCIONTime


class RequestHandler(object):
    """
    Small utility class to queue requests, check if they've been fulfilled, and
    send replies. Requests are expired after a certain period.

    This class is intended to be used in a seperate thread (run via
    RequestHandler.start()), and monitors a queue.Queue for notifications. To
    add a new request, the client code adds a key and request object to the
    queue. To signal that the RequestHandler should check for fulfilled queries
    for a given key, the client can simply send `None` instead of a request
    object.

    RequestHandler expects 4 parameters:
        - a queue to read from (discussed above)
        - a 'check' callback to see if a request can be fulfilled
        - a 'fetch' callback to send a query for the answer
        - a 'reply' callback to send the answer back to the requester
    """
    TTL = 2.0
    MAX_LEN = 16

    def __init__(self, queue, check, fetch, reply, ttl=TTL,
                 key_map=None):  # pragma: no cover
        """
        :param queue.Queue queue:
            Used to receive request notifications, see class docstring for
            details.
        :param function check:
            Called with the provided key, should return `True` if the request
            can be answered, otherwise `False`.
        :param function fetch:
            Called with the provided key and request info, responsible for
            fetching the answer for the request.
        :param function reply:
            Called with the provided key and request info, should return the
            result to the requester.
        """
        self._queue = queue
        self._check = check
        self._fetch = fetch
        self._reply = reply
        self._ttl = ttl
        self._req_map = defaultdict(list)
        self._key_map = key_map or self._def_key_map

    @classmethod
    def start(cls, name, *args, **kwargs):  # pragma: no cover
        """
        Create a queue and a RequestHandler object with the supplied
        args/kwargs, then start RequestHandler.run in a thread, and return the
        queue to the caller. This is the recommended way of running
        RequestHandler.
        """
        q = queue.Queue()
        inst = cls(q, *args, **kwargs)
        threading.Thread(
            target=thread_safety_net, args=(inst.run,),
            name=name, daemon=True).start()
        return q

    def run(self):
        while True:
            key, req = self._queue.get()
            if req:
                # Add a new request
                self._add_req(key, req)
            # Answer existing requests, if possible.
            for k in self._key_map(key, self._req_map.keys()):
                self._answer_reqs(k)

    def _add_req(self, key, request):
        self._expire_reqs(key)
        if not self._check(key):
            self._fetch(key, request)
        self._req_map[key].append((SCIONTime.get_time(), request))

    def _answer_reqs(self, key):
        if not self._check(key):
            # Don't have the answer yet.
            return
        self._expire_reqs(key)
        reqs = self._req_map[key]
        while reqs:
            _, req = reqs.pop(0)
            self._reply(key, req)
        del self._req_map[key]

    def _expire_reqs(self, key):
        if key not in self._req_map:
            return
        now = SCIONTime.get_time()
        count = 0
        for ts, req in self._req_map[key][:]:
            if now - ts > self._ttl:
                count += 1
                self._req_map[key].remove((ts, req))
        if count:
            logging.debug("Expired %d requests for %s", count, key)

    @staticmethod
    def _def_key_map(key, keys):  # pragma: no cover
        if key in keys:
            return [key]
        return []
