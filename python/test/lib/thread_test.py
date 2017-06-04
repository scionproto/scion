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
:mod:`lib_thread_test` --- lib.thread unit tests
=====================================================
"""

# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.thread import thread_safety_net


class TestThreadSafetyNet(object):
    """
    Unit tests for lib.thread.thread_safety_net
    """
    def no_exception_f(self):
        return "test_data"

    def exception_f(self):
        raise Exception('')
        return "test_data"

    @patch("lib.thread.kill_self", autospec=True)
    @patch("lib.thread.log_exception", autospec=True)
    def test_exception(self, log_test, kill_test):
        ntools.assert_is_none(thread_safety_net(self.exception_f))
        log_test.assert_called_once_with("Exception in %s thread:",
                                         "MainThread")
        kill_test.assert_called_once_with()

    def test_no_exception(self):
        ntools.eq_(thread_safety_net(self.no_exception_f), "test_data")

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
