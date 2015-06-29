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
# Stdlib
import unittest
from unittest.mock import patch


def noop_decorator(*args, **kwargs):
    """
    A no-op decorator, to allow testing of decorated functions/methods.

    :param args: positional arguments.
    :type args: list
    :param kwargs: dictionary with keyword arguments and their values.
    :type kwargs: dict
    """
    def wrap(f):
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper
    return wrap

# Replace thread_safey_net decorator with noop_decorator, to allow testing.
# This has to be done before any source that uses the decorator is imported.
patch('lib.thread.thread_safety_net', noop_decorator).start()


class SCIONTestException(Exception):
    """
    SCIONTestException class.
    """
    pass


class SCIONCommonTest(unittest.TestCase):
    """
    SCIONCommonTest class.
    """
    pass


class MockCollection(object):
    """
    A wrapper class to automate patching (and unpatching) multiple objects. To
    be used from a unittesting decorator.
    """
    def __init__(self):
        """
        Initialize an instance of the class MockCollection.
        """
        self._patcher = {}

    def add(self, target, name, new=None, autospec=True):
        """
        Create a patcher for `target`, and use `name` for the mock object made
        available after `start()`.

        :param target:
        :type target:
        :param name:
        :type name:
        :param new:
        :type new:
        :param autospec:
        :type autospec:
        """
        # Don't redo an existing patch
        if name in self._patcher:
            return
        kwargs = {}
        if new is None:
            kwargs["autospec"] = autospec
        else:
            kwargs["new"] = new
        self._patcher[name] = patch(target, **kwargs)

    def start(self):
        """
        Start all patchers, and use the stored `name`s to make the mock objects
        available.
        """
        for name, patcher in self._patcher.items():
            # Make sure we don't start a patcher twice
            if not hasattr(self, name):
                setattr(self, name, patcher.start())

    def stop(self):
        """
        Stop all patchers, and delete the mock object references.
        """
        for name, patcher in self._patcher.items():
            patcher.stop()
            delattr(self, name)
