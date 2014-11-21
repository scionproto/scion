"""
opaque_field_test.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from lib.packet.opaque_field import *
import unittest

class TestOpaqueFields(unittest.TestCase):
    """
    Unit tests for opaque_field.py.
    """

    def test_opaque_field(self):
        of = OpaqueField()
        self.assertEqual(of.info, OpaqueFieldType.NORMAL_OF)
        self.assertFalse(of.parsed)
        self.assertFalse(of.raw)

    def test_equality(self):
        """
        Make sure that equality tests between opaque fields only succeeds for
        the same type of opaque fields.
        """
        of1 = OpaqueField()
        of2 = OpaqueField()
        hof1 = HopOpaqueField()
        hof2 = HopOpaqueField()
        iof1 = InfoOpaqueField()
        iof2 = InfoOpaqueField()
        self.assertEqual(of1, of2)
        self.assertEqual(hof1, hof2)
        self.assertEqual(iof1, iof2)
        self.assertNotEqual(of1, hof1)
        self.assertNotEqual(iof1, hof1)
        self.assertNotEqual(of1, iof1)

    def test_hop_opaque_field(self):
        """
        Ensure that parsing a packed opaque field results in the same opaque
        field.
        """
        of = HopOpaqueField()
        ofCopy = HopOpaqueField()
        ofCopy.parse(of.pack())
        self.assertEqual(of, ofCopy)

if __name__ == "__main__":
    unittest.main()
