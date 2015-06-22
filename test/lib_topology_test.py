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
:mod:`lib_topology_test` --- SCION topology tests
=================================================
"""
# Stdlib
from ipaddress import ip_address
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.topology import (
    Element
)


class TestElementInit(object):
    """
    Unit tests for lib.topology.Element construction.
    """
    def test_basic(self):
        elem = Element()
        ntools.assert_is_none(elem.addr)
        ntools.assert_is_none(elem.name)

    @patch('lib.topology.ip_address')
    def test_ip_addr(self, ip_addr):
        Element('192.168.0.1')
        ip_addr.assert_called_with('192.168.0.1')

    def test_name_basic(self):
        elem = Element(name='localhost')
        ntools.assert_equal(elem.name, 'localhost')

    def test_name_numeric(self):
        elem = Element(name=42)
        ntools.assert_equal(elem.name, '42')

    def test_invalid_addr_type(self):
        ntools.assert_raises(ValueError, Element, '42.42.42.42.42')

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
