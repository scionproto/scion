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
from unittest.mock import MagicMock

# External
import nose.tools as ntools

# SCION
from lib.errors import SCIONBaseError


class SCIONTestError(SCIONBaseError):
    pass


def create_mock(attrs=None, class_=None):
    if attrs is None:
        attrs = []
    if class_:
        attrs.append("__class__")
    m = MagicMock(spec_set=attrs)
    if class_:
        m.__class__ = class_
    for attr in attrs:
        value = MagicMock(spec_set=[])
        if attr == "__class__" and class_:
            value = class_
        setattr(m, attr, value)
    return m


def create_mock_full(kv=None, class_=None, return_value=None, side_effect=None):
    """
    'kv' is a dict
    "attr": val - directly sets attr to val.
    "attr()": val - sets the return value of attr() to val.
    "attr()...": val - sets the side_effects of attr() to val.
    """
    def base(name):
        return name.rstrip("().")
    if not kv:
        kv = {}
    attrs = []
    for k in kv:
        attrs.append(base(k))
    m = create_mock(attrs, class_=class_)
    if return_value is not None:
        m.return_value = return_value
    if side_effect is not None:
        m.side_effect = side_effect
    for k, v in kv.items():
        a = base(k)
        if k.endswith("()..."):
            f = getattr(m, a)
            setattr(f, "side_effect", v)
        elif k.endswith("()"):
            f = getattr(m, a)
            setattr(f, "return_value", v)
        else:
            setattr(m, a, v)
    return m


def assert_these_calls(mock, calls, any_order=False):
    mock.assert_has_calls(calls, any_order=any_order)
    ntools.eq_(len(mock.mock_calls), len(calls))


def assert_these_call_lists(mock, call_lists, any_order=False):
    calls = []
    for x in call_lists:
        calls.extend(x.call_list())
    assert_these_calls(mock, calls, any_order=any_order)
