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
:mod:`lib_main_test` --- lib.main unit tests
============================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.main import main_wrapper
from test.testcommon import create_mock


class TestMainWrapper(object):
    """
    Unit tests for lib.main.main_wrapper
    """
    def test_basic(self):
        main = create_mock()
        # Call
        main_wrapper(main, "arg1", arg2="arg2")
        # Tests
        main.assert_called_once_with("arg1", arg2="arg2")

    def test_sysexit(self):
        main = create_mock()
        main.side_effect = SystemExit
        # Call
        ntools.assert_raises(SystemExit, main_wrapper, main)

    @patch("lib.main.sys.exit", autospec=True)
    @patch("lib.main.log_exception", autospec=True)
    def test_excp(self, log_excp, exit):
        main = create_mock()
        main.side_effect = KeyError
        # Call
        main_wrapper(main)
        # Tests
        ntools.ok_(log_excp.called)
        ntools.ok_(exit.called)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
