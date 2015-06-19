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
from ipaddress import IPv4Address, IPv6Address

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

    def test_ipv4(self):
        elem = Element('192.168.0.1')
        ntools.assert_equal(elem.addr, IPv4Address('192.168.0.1'))
        ntools.assert_is_instance(elem.addr, IPv4Address)
        ntools.assert_is_none(elem.name)

    def test_ipv6(self):
        elem = Element('2001:db8::')
        ntools.assert_equal(elem.addr, IPv6Address('2001:db8::'))
        ntools.assert_is_instance(elem.addr, IPv6Address)
        ntools.assert_is_none(elem.name)

    def test_name_basic(self):
        elem = Element(None, 'localhost')
        ntools.assert_is_none(elem.addr)
        ntools.assert_is_not_none(elem.name)
        ntools.assert_equal(elem.name, 'localhost')

    def test_name_numeric(self):
        elem = Element(None, 42)
        ntools.assert_is_none(elem.addr)
        ntools.assert_is_not_none(elem.name)
        ntools.assert_equal(elem.name, '42')

    def test_invalid_addr_type(self):
        ntools.assert_raises(ValueError, Element, '42.42.42.42.42')

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
