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
:mod:`topology_test` --- SCION topology tests
=============================================
"""
# Stdlib
#from unittest.mock import patch
from ipaddress import IPv4Address, IPv6Address

# External packages
import nose
import nose.tools as ntools
#import bitstring
#from bitstring import BitArray

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
        ntools.assert_is_none(elem.addr_type)
        ntools.assert_is_none(elem.to_addr)
        ntools.assert_is_none(elem.name)

    def test_ipv4(self):
        elem = Element('192.168.0.1', 'ipv4')
        ntools.assert_equal(elem.addr, IPv4Address('192.168.0.1'))
        ntools.assert_is_instance(elem.addr, IPv4Address)
        ntools.assert_equal(elem.addr_type, 'ipv4')
        ntools.assert_is_none(elem.to_addr)
        ntools.assert_is_none(elem.name)

    def test_ipv6(self):
        elem = Element('2001:db8::', 'ipv6')
        ntools.assert_equal(elem.addr, IPv6Address('2001:db8::'))
        ntools.assert_is_instance(elem.addr, IPv6Address)
        ntools.assert_equal(elem.addr_type, 'ipv6')
        ntools.assert_is_none(elem.to_addr)
        ntools.assert_is_none(elem.name)

    def test_name_basic(self):
        elem = Element(name='localhost')
        ntools.assert_is_none(elem.addr)
        ntools.assert_is_none(elem.addr_type)
        ntools.assert_is_none(elem.to_addr)
        ntools.assert_is_not_none(elem.name)
        ntools.assert_equal(elem.name, 'localhost')

    def test_name_numeric(self):
        elem = Element(name=42)
        ntools.assert_is_none(elem.addr)
        ntools.assert_is_none(elem.addr_type)
        ntools.assert_is_none(elem.to_addr)
        ntools.assert_is_not_none(elem.name)
        ntools.assert_equal(elem.name, '42')

    def test_to_addr_ipv4(self):
        elem = Element('192.168.0.1', 'ipv4', '192.168.1.1')
        ntools.assert_equal(elem.addr, IPv4Address('192.168.0.1'))
        ntools.assert_is_instance(elem.addr, IPv4Address)
        ntools.assert_equal(elem.addr_type, 'ipv4')
        ntools.assert_equal(elem.to_addr, IPv4Address('192.168.1.1'))
        ntools.assert_is_none(elem.name)

    def test_to_addr_ipv6(self):
        elem = Element('2001:db8::', 'ipv6', '::1')
        ntools.assert_equal(elem.addr, IPv6Address('2001:db8::'))
        ntools.assert_is_instance(elem.addr, IPv6Address)
        ntools.assert_equal(elem.addr_type, 'ipv6')
        ntools.assert_equal(elem.to_addr, IPv6Address('::1'))
        ntools.assert_is_none(elem.name)

    def test_invalid_addr_type(self):
        elem = Element('42.42.42.42.42', 'ipv5')
        ntools.assert_is_none(elem.addr)
        ntools.assert_is_none(elem.addr_type)
        ntools.assert_is_none(elem.to_addr)
        ntools.assert_is_none(elem.name)

    def test_uppercase_addr_type(self):
        elem = Element('192.168.0.1', 'IPv4')
        ntools.assert_equal(elem.addr, IPv4Address('192.168.0.1'))
        ntools.assert_is_instance(elem.addr, IPv4Address)
        ntools.assert_equal(elem.addr_type, 'ipv4')
        ntools.assert_is_none(elem.to_addr)
        ntools.assert_is_none(elem.name)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
