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
:mod:`lib_requests_test` --- lib.requests unit tests
====================================================
"""

# Stdlib
from unittest.mock import call, patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.requests import (
    RequestHandler,
)
from test.testcommon import assert_these_calls, create_mock, create_mock_full


class TestRequestHandlerRun(object):
    """
    Unit tests for lib.requests.RequestHandler.run
    """
    def test(self):
        q = create_mock(["get"])
        q.get.side_effect = [("key0", "req0"), ("key1", None)]
        inst = RequestHandler(q, "check", "fetch", "reply")
        inst._add_req = create_mock()
        inst._answer_reqs = create_mock()
        inst._key_map = create_mock()
        inst._key_map.side_effect = ("key0map0", "key0map1"), ("key1map0",)
        # Call
        ntools.assert_raises(StopIteration, inst.run)
        # Tests
        inst._add_req.assert_called_once_with("key0", "req0")
        assert_these_calls(inst._answer_reqs, [
            call("key0map0"), call("key0map1"), call("key1map0")])


class TestRequestHandlerAddReq(object):
    """
    Unit tests for lib.requests.RequestHandler._add_req
    """
    def _setup(self, time_, check_ret):
        check = create_mock_full(return_value=check_ret)
        fetch = create_mock()
        inst = RequestHandler("queue", check, fetch, "reply")
        inst._expire_reqs = create_mock()
        time_.return_value = 2
        return inst

    @patch("lib.requests.SCIONTime.get_time", newcallable=create_mock)
    def test_no_ans_no_query(self, time_):
        inst = self._setup(time_, False)
        # Call
        inst._add_req("key", "req")
        # Tests
        inst._expire_reqs.assert_called_once_with("key")
        inst._check.assert_called_once_with("key")
        inst._fetch.assert_called_once_with("key", "req")
        ntools.eq_(inst._req_map["key"], [(2, "req")])

    @patch("lib.requests.SCIONTime.get_time", newcallable=create_mock)
    def test_ans(self, time_):
        inst = self._setup(time_, True)
        inst._req_map["key"] = [(1, "oldreq")]
        # Call
        inst._add_req("key", "req")
        # Tests
        ntools.assert_false(inst._fetch.called)
        ntools.eq_(inst._req_map["key"], [(1, "oldreq"), (2, "req")])


class TestRequestHandlerAnswerReqs(object):
    """
    Unit tests for lib.requests.RequestHandler._answer_reqs
    """
    def _setup(self, check_ret=True):
        check = create_mock()
        check.return_value = check_ret
        reply = create_mock()
        inst = RequestHandler("queue", check, "fetch", reply)
        inst._expire_reqs = create_mock()
        return inst

    def test_no_ans(self):
        inst = self._setup(False)
        inst._req_map["key"] = ["req0"]
        # Call
        inst._answer_reqs("key")
        # Tests
        ntools.eq_(inst._req_map["key"], ["req0"])
        ntools.assert_false(inst._expire_reqs.called)

    def test_reqs(self):
        inst = self._setup()
        inst._req_map["key"] = [(0, "req0"), (1, "req1"), (2, "req2")]
        # Call
        inst._answer_reqs("key")
        # Tests
        inst._expire_reqs.assert_called_once_with("key")
        assert_these_calls(inst._reply, [
            call("key", "req0"), call("key", "req1"), call("key", "req2")
        ])
        ntools.assert_not_in("key", inst._req_map)


class TestRequestHandlerExpireReqs(object):
    """
    Unit tests for lib.requests.RequestHandler._expire_reqs
    """
    def test_no_reqs(self):
        inst = RequestHandler("queue", "check", "fetch", "reply")
        # Call
        inst._expire_reqs("key")

    @patch("lib.requests.SCIONTime.get_time", newcallable=create_mock)
    def test_reqs(self, time_):
        inst = RequestHandler("queue", "check", "fetch", "reply", ttl=5)
        inst._req_map["key"] = [(0, "req0"), (1, "req1"), (2, "req2")]
        time_.return_value = 6
        # Call
        inst._expire_reqs("key")
        # Tests
        ntools.eq_(inst._req_map["key"], [(1, "req1"), (2, "req2")])


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
