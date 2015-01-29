"""
path_store_test.py

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

from lib.path_store import *
import unittest


class TestPathStore(unittest.TestCase):
    """
    Unit tests for path_store_test.py.
    """

    def test(self):
        """
        Creates a half path beacon and inserts it in a path store. Also, the
        path store's policy gets updated.
        """
        path_store = PathStore('./ps.xml')
        raw = (b'\x80\x00\x02\x00\x0b\x01\x00\x00\xff\x00\x00\x00\x00\x00\x01' +
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' +
            b'\x00 \x00\x00\x00\x00\x03\x00\x00\x00\x00\x0b\x00\x00\x00\x00' +
            b'\x00\x00')
        pcb = PathSegment(raw)
        print(str(path_store), "\n\n")
        path_store.update_policy('./ps.xml')
        print(str(path_store), "\n\n")
        path_store.store_selection()
        bests = path_store.get_paths()
        for best in bests:
            print(str(best))

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
