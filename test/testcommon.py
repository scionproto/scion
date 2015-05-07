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
:mod:`testcommon` --- Common test classes/utilities
===================================================
"""

import unittest


class SCIONTestException(Exception):
    pass


class SCIONCommonTest(unittest.TestCase):
    def shortDescription(self):
        """
        Tell nosetests not to use a test method's docstring to identify the
        test
        """
        return None
