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
:mod:`path_store_test` --- SCION path store unit test
=========================================================
"""

from Crypto import Random
from lib.crypto.asymcrypto import sign
from lib.crypto.hash_chain import HashChain
from lib.packet.opaque_field import (OpaqueFieldType as OFT, InfoOpaqueField,
    SupportSignatureField, HopOpaqueField, SupportPCBField, SupportPeerField,
    TRCField)
from lib.packet.pcb import (PathSegment, ADMarking, PCBMarking, PeerMarking,
    PathConstructionBeacon)
from lib.path_store import PathPolicy, PathStore
from lib.util import read_file, get_sig_key_file_path, sleep_interval
import base64
import logging
import threading
import time
import unittest


class TestPathStore(unittest.TestCase):
    """
    Unit tests for path_store.py.
    """

    def _create_ad_marking(self):
        """
        Creates an AD Marking with the given ingress and egress interfaces.
        """
        ssf = SupportSignatureField.from_values(ADMarking.LEN)
        hof = HopOpaqueField.from_values(0.25, 111, 222)
        spcbf = SupportPCBField.from_values(1)
        rev_token = HashChain(Random.new().read(32)).next_element()
        pcbm = PCBMarking.from_values(10, ssf, hof, spcbf, rev_token, rev_token)
        peer_markings = []
        signing_key = read_file(get_sig_key_file_path(1, 10))
        signing_key = base64.b64decode(signing_key)
        data_to_sign = (b'11' + pcbm.hof.pack() + pcbm.spcbf.pack())
        signature = sign(data_to_sign, signing_key)
        return ADMarking.from_values(pcbm, peer_markings, signature)

    def test(self):
        """
        
        """
        path_policy_file = "../topology/ISD1/path_policies/ISD:1-AD:10.json"
        path_policy = PathPolicy(path_policy_file)
        test_segments = PathStore(path_policy)
        print("Paths in path store: " + str(len(test_segments.candidates)))

        path = 1
        for _ in range(1, 4):
            for _ in range(1, 4):
                pcb = PathSegment()
                pcb.segment_id = HashChain(Random.new().read(32)).next_element()
                pcb.iof = InfoOpaqueField.from_values(OFT.TDC_XOVR, False,
                                                      int(time.time()), path)
                pcb.trcf = TRCField()
                ad_marking = self._create_ad_marking()
                pcb.add_ad(ad_marking)
                print("insert path " + str(path) + ", exp time: " +
                      str(pcb.get_expiration_time()))
                test_segments.add_segment(pcb)
                path += 1
            sleep_interval(int(time.time()), 60, "Wait before adding...")
            print("Paths in path store: " + str(len(test_segments.candidates)))
            print("Time: " + str(int(time.time())))
        
        print("Select the best ones...")
        test_segments.get_best_segments()
        print("Paths in path store: " + str(len(test_segments.candidates)))
        print("Store paths in history...")
        test_segments.store_selection()
        print("Paths in path store: " + str(len(test_segments.candidates)))


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
