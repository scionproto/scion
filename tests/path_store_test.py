#!/usr/bin/python3
# Copyright 2014 ETH Zurich
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
:mod:`path_store_test` --- SCION path store integration test
============================================================
"""
# Stdlib
import base64
import logging
import os
import time
import unittest

# SCION
from lib.crypto.asymcrypto import sign
from lib.crypto.hash_chain import HashChain
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
)
from lib.packet.pcb import ADMarking, PCBMarking, PathSegment
from lib.path_store import PathPolicy, PathStore
from lib.types import OpaqueFieldType as OFT
from lib.util import get_sig_key_file_path, read_file


class TestPathStore(unittest.TestCase):
    """
    Unit tests for path_store.py.
    """

    def _create_ad_marking(self):
        """
        Create an AD Marking with the given ingress and egress interfaces.
        """
        hof = HopOpaqueField.from_values(1, 111, 222)
        rev_token = HashChain(os.urandom(32)).next_element()
        pcbm = PCBMarking.from_values(1, 10, hof)
        peer_markings = []
        signing_key = read_file(get_sig_key_file_path(1, 10))
        signing_key = base64.b64decode(signing_key)
        data_to_sign = (b'11' + pcbm.hof.pack())
        signature = sign(data_to_sign, signing_key)
        return ADMarking.from_values(pcbm, peer_markings, rev_token, signature)

    def test(self):
        """
        Test the main functionalities of the path store.
        """
        path_policy_file = "topology/ISD1/path_policies/ISD1-AD10.json"
        path_policy = PathPolicy.from_file(path_policy_file)
        test_segments = PathStore(path_policy)
        print("Best paths: " + str(len(test_segments.get_best_segments())))
        print("Paths in path store: " + str(len(test_segments.candidates)))
        print("Paths in latest history snapshot: " +
              str(len(test_segments.get_latest_history_snapshot())) + "\n")

        path = 1
        for _ in range(1, 6):
            for _ in range(1, 6):
                pcb = PathSegment()
                pcb.iof = InfoOpaqueField.from_values(OFT.TDC_XOVR, False,
                                                      int(time.time()), path)
                ad_marking = self._create_ad_marking()
                pcb.add_ad(ad_marking)
                print("insert path " + str(path) + ", exp time: " +
                      str(pcb.get_expiration_time()))
                test_segments.add_segment(pcb)
                path += 1
            print("Best paths: " + str(len(test_segments.get_best_segments())))
            print("Paths in path store: " + str(len(test_segments.candidates)))
            print("Paths in latest history snapshot: " +
                  str(len(test_segments.get_latest_history_snapshot())))
            print("Time: " + str(int(time.time())) + "\n")
            time.sleep(5)

        print("Waiting for some paths to expire...")
        time.sleep(25)
        print("Best paths: " + str(len(test_segments.get_best_segments())))
        print("Paths in path store: " + str(len(test_segments.candidates)))
        print("Paths in latest history snapshot: " +
              str(len(test_segments.get_latest_history_snapshot())))


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
