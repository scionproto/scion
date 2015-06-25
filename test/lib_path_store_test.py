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
:mod:`lib_path_store_test` --- lib.path_store unit tests
==========================================================================
"""
# Stdlib
from unittest.mock import patch, mock_open, MagicMock

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.pcb import PathSegment
from lib.path_store import (
    PathPolicy,
    PathStoreRecord
)


class TestPathPolicyInit(object):
    """
    Unit tests for lib.path_store.PathPolicy.__init__
    """
    def test_basic(self):
        pth_pol = PathPolicy()
        ntools.eq_(pth_pol.best_set_size, 5)
        ntools.eq_(pth_pol.candidates_set_size, 20)
        ntools.eq_(pth_pol.history_limit, 0)
        ntools.eq_(pth_pol.update_after_number, 0)
        ntools.eq_(pth_pol.update_after_time, 0)
        ntools.eq_(pth_pol.unwanted_ads, [])
        ntools.eq_(pth_pol.property_ranges, {})
        ntools.eq_(pth_pol.property_weights, {})


class TestPathPolicyGetPathPolicyDict(object):
    """
    Unit tests for lib.path_store.PathPolicy.get_path_policy_dict
    """
    def test_basic(self):
        pth_pol = PathPolicy()
        pth_pol.best_set_size = "best_set_size"
        pth_pol.candidates_set_size = "candidates_set_size"
        pth_pol.history_limit = "history_limit"
        pth_pol.update_after_number = "update_after_number"
        pth_pol.update_after_time = "update_after_time"
        pth_pol.unwanted_ads = "unwanted_ads"
        pth_pol.property_ranges = "property_ranges"
        pth_pol.property_weights = "property_weights"
        dict_ = pth_pol.get_path_policy_dict()
        ntools.eq_(dict_['best_set_size'], "best_set_size")
        ntools.eq_(dict_['candidates_set_size'], "candidates_set_size")
        ntools.eq_(dict_['history_limit'], "history_limit")
        ntools.eq_(dict_['update_after_number'], "update_after_number")
        ntools.eq_(dict_['update_after_time'], "update_after_time")
        ntools.eq_(dict_['unwanted_ads'], "unwanted_ads")
        ntools.eq_(dict_['property_ranges'], "property_ranges")
        ntools.eq_(dict_['property_weights'], "property_weights")
        ntools.eq_(len(dict_), 8)


@patch("lib.path_store.logging.warning")
class TestPathPolicyCheckFilters(object):
    """
    Unit tests for lib.path_store.PathPolicy.check_filters
    """
    def test_basic(self, wrng):
        pcb = MagicMock(spec_set=['__class__'])
        pcb.__class__ = PathSegment
        pth_pol = PathPolicy()
        pth_pol._check_unwanted_ads = MagicMock()
        pth_pol._check_unwanted_ads.return_value = True
        pth_pol._check_property_ranges = MagicMock()
        pth_pol._check_property_ranges.return_value = True
        ntools.assert_true(pth_pol.check_filters(pcb))
        ntools.eq_(wrng.call_count, 0)

    def test_unwanted_ads(self, wrng):
        pcb = MagicMock(spec_set=['__class__'])
        pcb.__class__ = PathSegment
        pth_pol = PathPolicy()
        pth_pol._check_unwanted_ads = MagicMock()
        pth_pol._check_unwanted_ads.return_value = False
        ntools.assert_false(pth_pol.check_filters(pcb))
        wrng.assert_called_once_with("PathStore: pcb discarded (unwanted AD).")

    def test_property_ranges(self, wrng):
        pcb = MagicMock(spec_set=['__class__'])
        pcb.__class__ = PathSegment
        pth_pol = PathPolicy()
        pth_pol._check_unwanted_ads = MagicMock()
        pth_pol._check_unwanted_ads.return_value = True
        pth_pol._check_property_ranges = MagicMock()
        pth_pol._check_property_ranges.return_value = False
        ntools.assert_false(pth_pol.check_filters(pcb))
        wrng.assert_called_once_with("PathStore: pcb discarded (property range)"
                                     ".")


class TestPathPolicyCheckUnwantedAds(object):
    """
    Unit tests for lib.path_store.PathPolicy._check_unwanted_ads
    """
    def test_basic(self):
        pcb = MagicMock(spec_set=['ads'])
        pcb.ads = [MagicMock(spec_set=['pcbm']) for i in range(5)]
        for i in range(5):
            pcb.ads[i].pcbm = MagicMock(spec_set=['isd_id', 'ad_id'])
            pcb.ads[i].pcbm.isd_id = "isd_id" + str(i)
            pcb.ads[i].pcbm.ad_id = "ad_id" + str(i)
        pth_pol = PathPolicy()
        pth_pol.unwanted_ads = [("isd_id1", "ad_id1")]
        ntools.assert_false(pth_pol._check_unwanted_ads(pcb))

    def test_not_present(self):
        pcb = MagicMock(spec_set=['ads'])
        pcb.ads = [MagicMock(spec_set=['pcbm']) for i in range(5)]
        for i in range(5):
            pcb.ads[i].pcbm = MagicMock(spec_set=['isd_id', 'ad_id'])
            pcb.ads[i].pcbm.isd_id = "isd_id" + str(i)
            pcb.ads[i].pcbm.ad_id = "ad_id" + str(i)
        pth_pol = PathPolicy()
        pth_pol.unwanted_ads = []
        ntools.assert_true(pth_pol._check_unwanted_ads(pcb))


class TestPathPolicyCheckPropertyRanges(object):
    """
    Unit tests for lib.path_store.PathPolicy._check_property_ranges
    """
    def __init__(self):
        self.d = {'PeerLinks': [], 'HopsLength': [], 'DelayTime': [],
                  'GuaranteedBandwidth': [], 'AvailableBandwidth': [],
                  'TotalBandwidth': []}

    def test_basic(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d.copy()
        ntools.assert_true(pth_pol._check_property_ranges("pcb"))

    def test_peer_link_true(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d.copy()
        pth_pol.property_ranges['PeerLinks'].extend([0, 2])
        pcb = MagicMock(spec_set=['get_n_peer_links'])
        pcb.get_n_peer_links.return_value = 1
        ntools.assert_true(pth_pol._check_property_ranges(pcb))

    def test_peer_link_false(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d.copy()
        pth_pol.property_ranges['PeerLinks'].extend([2, 0])
        pcb = MagicMock(spec_set=['get_n_peer_links'])
        pcb.get_n_peer_links.return_value = 1
        ntools.assert_false(pth_pol._check_property_ranges(pcb))

    def test_hop_length_true(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d.copy()
        pth_pol.property_ranges['HopsLength'].extend([0, 2])
        pcb = MagicMock(spec_set=['get_n_hops'])
        pcb.get_n_hops.return_value = 1
        ntools.assert_true(pth_pol._check_property_ranges(pcb))

    def test_hop_length_false(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d.copy()
        pth_pol.property_ranges['HopsLength'].extend([2, 0])
        pcb = MagicMock(spec_set=['get_n_hops'])
        pcb.get_n_hops.return_value = 1
        ntools.assert_false(pth_pol._check_property_ranges(pcb))

    @patch("lib.path_store.time.time", autospec=True)
    def test_delay_time_true(self, time_):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d.copy()
        pth_pol.property_ranges['DelayTime'].extend([0, 2])
        pcb = MagicMock(spec_set=['get_timestamp'])
        pcb.get_timestamp.return_value = 1
        time_.return_value = 2
        ntools.assert_true(pth_pol._check_property_ranges(pcb))
        time_.assert_called_once_with()

    @patch("lib.path_store.time.time", autospec=True)
    def test_delay_time_false(self, time_):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d.copy()
        pth_pol.property_ranges['DelayTime'].extend([2, 0])
        pcb = MagicMock(spec_set=['get_timestamp'])
        pcb.get_timestamp.return_value = 1
        time_.return_value = 2
        ntools.assert_false(pth_pol._check_property_ranges(pcb))

    def test_guaranteed_bandwidth_true(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d.copy()
        pth_pol.property_ranges['GuaranteedBandwidth'].extend([0, 20])
        ntools.assert_true(pth_pol._check_property_ranges("pcb"))

    def test_guaranteed_bandwidth_false(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d.copy()
        pth_pol.property_ranges['GuaranteedBandwidth'].extend([20, 0])
        ntools.assert_false(pth_pol._check_property_ranges("pcb"))

    def test_available_bandwidth_true(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d.copy()
        pth_pol.property_ranges['AvailableBandwidth'].extend([0, 20])
        ntools.assert_true(pth_pol._check_property_ranges("pcb"))

    def test_available_bandwidth_false(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d.copy()
        pth_pol.property_ranges['AvailableBandwidth'].extend([20, 0])
        ntools.assert_false(pth_pol._check_property_ranges("pcb"))

    def test_total_bandwidth_true(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d.copy()
        pth_pol.property_ranges['TotalBandwidth'].extend([0, 20])
        ntools.assert_true(pth_pol._check_property_ranges("pcb"))

    def test_total_bandwidth_false(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d.copy()
        pth_pol.property_ranges['TotalBandwidth'].extend([20, 0])
        ntools.assert_false(pth_pol._check_property_ranges("pcb"))


class TestPathPolicyFromFile(object):
    """
    Unit tests for lib.path_store.PathPolicy.from_file
    """
    @patch("lib.path_store.PathPolicy.from_dict", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.path_store.json.load", autospec=True)
    def test_basic(self, load, from_dict):
        load.return_value = "policy_dict"
        from_dict.return_value = "from_dict"
        with patch('lib.path_store.open', mock_open(), create=True) as open_f:
            ntools.eq_(PathPolicy.from_file("policy_file"), "from_dict")
            open_f.assert_called_once_with("policy_file")
            load.assert_called_once_with(open_f.return_value)
            from_dict.assert_called_once_with("policy_dict")


class TestPathPolicyFromDict(object):
    """
    Unit tests for lib.path_store.PathPolicy.from_dict
    """
    @patch("lib.path_store.PathPolicy.parse_dict", autospec=True)
    def test_basic(self, parse_dict):
        pth_pol = PathPolicy.from_dict("policy_dict")
        parse_dict.assert_called_once_with(pth_pol, "policy_dict")
        ntools.assert_is_instance(pth_pol, PathPolicy)


class TestPathPolicyParseDict(object):
    """
    Unit tests for lib.path_store.PathPolicy.parse_dict
    """
    def test_basic(self):
        dict_ = {}
        dict_['BestSetSize'] = "best_set_size"
        dict_['CandidatesSetSize'] = "candidates_set_size"
        dict_['HistoryLimit'] = "history_limit"
        dict_['UpdateAfterNumber'] = "update_after_number"
        dict_['UpdateAfterTime'] = "update_after_time"
        dict_['UnwantedADs'] = "1-11,2-12"
        dict_['PropertyRanges'] = {'key1': "1-11", 'key2': "2-12"}
        dict_['PropertyWeights'] = "property_weights"
        pth_pol2 = PathPolicy()
        pth_pol2.parse_dict(dict_)
        ntools.eq_(pth_pol2.best_set_size, "best_set_size")
        ntools.eq_(pth_pol2.candidates_set_size, "candidates_set_size")
        ntools.eq_(pth_pol2.history_limit, "history_limit")
        ntools.eq_(pth_pol2.update_after_number, "update_after_number")
        ntools.eq_(pth_pol2.update_after_time, "update_after_time")
        ntools.eq_(pth_pol2.unwanted_ads, [(1, 11), (2, 12)])
        ntools.eq_(pth_pol2.property_ranges['key1'], (1, 11))
        ntools.eq_(pth_pol2.property_ranges['key2'], (2, 12))
        ntools.eq_(len(pth_pol2.property_ranges), 2)
        ntools.eq_(pth_pol2.property_weights, "property_weights")


class TestPathStoreRecordInit(object):
    """
    Unit tests for lib.path_store.PathStoreRecord.__init__
    """
    @patch("lib.path_store.time.time")
    def test_basic(self, time_):
        pcb = MagicMock(spec_set=['__class__', 'segment_id',
                                  'get_expiration_time'])
        pcb.__class__ = PathSegment
        pcb.segment_id = "id"
        pcb.get_expiration_time.return_value = "get_expiration_time"
        time_.return_value = 23
        pth_str_rec = PathStoreRecord(pcb)
        ntools.eq_(pth_str_rec.pcb, pcb)
        ntools.eq_(pth_str_rec.id, pcb.segment_id)
        ntools.eq_(pth_str_rec.fidelity, 0)
        ntools.eq_(pth_str_rec.peer_links, 0)
        ntools.eq_(pth_str_rec.hops_length, 0)
        ntools.eq_(pth_str_rec.disjointness, 0)
        ntools.eq_(pth_str_rec.last_sent_time, 1420070400)
        ntools.eq_(pth_str_rec.last_seen_time, 23)
        ntools.eq_(pth_str_rec.delay_time, 0)
        ntools.eq_(pth_str_rec.expiration_time, "get_expiration_time")
        ntools.eq_(pth_str_rec.guaranteed_bandwidth, 0)
        ntools.eq_(pth_str_rec.available_bandwidth, 0)
        ntools.eq_(pth_str_rec.total_bandwidth, 0)
        time_.assert_called_once_with()
        pcb.get_expiration_time.assert_called_once_with()


class TestPathStoreRecordUpdateFidelity(object):
    """
    Unit tests for lib.path_store.PathStoreRecord.update_fidelity
    """
    @patch("lib.path_store.time.time")
    def test_basic(self, time_):
        path_policy = PathPolicy()
        path_policy.property_weights['PeerLinks'] = 10
        path_policy.property_weights['HopsLength'] = 1
        path_policy.property_weights['Disjointness'] = 2
        path_policy.property_weights['LastSentTime'] = 3
        path_policy.property_weights['LastSeenTime'] = 4
        path_policy.property_weights['DelayTime'] = 5
        path_policy.property_weights['ExpirationTime'] = 6
        path_policy.property_weights['GuaranteedBandwidth'] = 7
        path_policy.property_weights['AvailableBandwidth'] = 8
        path_policy.property_weights['TotalBandwidth'] = 9
        pcb = MagicMock(spec_set=['__class__', 'segment_id',
                                  'get_expiration_time'])
        pcb.__class__ = PathSegment
        pth_str_rec = PathStoreRecord(pcb)
        pth_str_rec.peer_links = 10 ** 5
        pth_str_rec.hops_length = (1 / (10 ** 4))
        pth_str_rec.disjointness = 10 ** 3
        pth_str_rec.last_sent_time = -99
        pth_str_rec.last_seen_time = 10
        pth_str_rec.delay_time = 1
        pth_str_rec.expiration_time = 10 / 9
        pth_str_rec.guaranteed_bandwidth = 10 ** -2
        pth_str_rec.available_bandwidth = 10 ** -3
        pth_str_rec.total_bandwidth = 10 ** -4
        time_.return_value = 1
        pth_str_rec.update_fidelity(path_policy)
        ntools.assert_almost_equal(pth_str_rec.fidelity, 1012345.6789)


class TestPathStoreRecordEQ(object):
    """
    Unit tests for lib.path_store.PathStoreRecord.__eq__
    """
    def __init__(self):
        self.pcb = MagicMock(spec_set=['__class__', 'segment_id',
                                       'get_expiration_time'])
        self.pcb.__class__ = PathSegment

    def test_eq(self):
        pth_str_rec1 = PathStoreRecord(self.pcb)
        pth_str_rec2 = PathStoreRecord(self.pcb)
        id_ = "id"
        pth_str_rec1.id = id_
        pth_str_rec2.id = id_
        ntools.eq_(pth_str_rec1, pth_str_rec2)

    def test_neq(self):
        pth_str_rec1 = PathStoreRecord(self.pcb)
        pth_str_rec2 = PathStoreRecord(self.pcb)
        pth_str_rec1.id = "id1"
        pth_str_rec2.id = "id2"
        ntools.assert_not_equals(pth_str_rec1, pth_str_rec2)

    def test_type_neq(self):
        pth_str_rec1 = PathStoreRecord(self.pcb)
        pth_str_rec2 = b'test'
        ntools.assert_not_equals(pth_str_rec1, pth_str_rec2)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
