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
    PathStore,
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
        keys = ["best_set_size", "candidates_set_size", "history_limit",
                "update_after_number", "update_after_time", "unwanted_ads",
                "property_ranges", "property_weights"]
        pth_pol = PathPolicy()
        target = {}
        for key in keys:
            setattr(pth_pol, key, key)
            target[key] = key
        dict_ = pth_pol.get_path_policy_dict()
        ntools.eq_(dict_, target)


@patch("lib.path_store.logging.warning", autospec=True)
class TestPathPolicyCheckFilters(object):
    """
    Unit tests for lib.path_store.PathPolicy.check_filters
    """
    def test_basic(self, wrng):
        pcb = MagicMock(spec_set=PathSegment)
        pth_pol = PathPolicy()
        pth_pol._check_unwanted_ads = MagicMock(spec_set=[])
        pth_pol._check_unwanted_ads.return_value = True
        pth_pol._check_property_ranges = MagicMock(spec_set=[])
        pth_pol._check_property_ranges.return_value = True
        ntools.assert_true(pth_pol.check_filters(pcb))
        ntools.eq_(wrng.call_count, 0)

    def test_unwanted_ads(self, wrng):
        pcb = MagicMock(spec_set=PathSegment)
        pth_pol = PathPolicy()
        pth_pol._check_unwanted_ads = MagicMock(spec_set=[])
        pth_pol._check_unwanted_ads.return_value = False
        ntools.assert_false(pth_pol.check_filters(pcb))
        ntools.eq_(wrng.call_count, 1)

    def test_property_ranges(self, wrng):
        pcb = MagicMock(spec_set=PathSegment)
        pth_pol = PathPolicy()
        pth_pol._check_unwanted_ads = MagicMock(spec_set=[])
        pth_pol._check_unwanted_ads.return_value = True
        pth_pol._check_property_ranges = MagicMock(spec_set=[])
        pth_pol._check_property_ranges.return_value = False
        ntools.assert_false(pth_pol.check_filters(pcb))
        ntools.eq_(wrng.call_count, 1)


class TestPathPolicyCheckUnwantedAds(object):
    """
    Unit tests for lib.path_store.PathPolicy._check_unwanted_ads
    """
    def setUp(self):
        self.pcb = MagicMock(spec_set=['ads'])
        self.pcb.ads = [MagicMock(spec_set=['pcbm']) for i in range(5)]
        for i in range(5):
            self.pcb.ads[i].pcbm = MagicMock(spec_set=['isd_id', 'ad_id'])
            self.pcb.ads[i].pcbm.isd_id = "isd_id" + str(i)
            self.pcb.ads[i].pcbm.ad_id = "ad_id" + str(i)
        self.pth_pol = PathPolicy()

    def tearDown(self):
        del self.pcb
        del self.pth_pol

    def test_basic(self):
        self.pth_pol.unwanted_ads = [("isd_id1", "ad_id1")]
        ntools.assert_false(self.pth_pol._check_unwanted_ads(self.pcb))

    def test_not_present(self):
        self.pth_pol.unwanted_ads = []
        ntools.assert_true(self.pth_pol._check_unwanted_ads(self.pcb))


class TestPathPolicyCheckPropertyRanges(object):
    """
    Unit tests for lib.path_store.PathPolicy._check_property_ranges
    """
    def setUp(self):
        self.d = {'PeerLinks': [], 'HopsLength': [], 'DelayTime': [],
                  'GuaranteedBandwidth': [], 'AvailableBandwidth': [],
                  'TotalBandwidth': []}

    def tearDown(self):
        del self.d

    def test_basic(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d
        ntools.assert_true(pth_pol._check_property_ranges("pcb"))

    def test_peer_link_true(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d
        pth_pol.property_ranges['PeerLinks'].extend([0, 2])
        pcb = MagicMock(spec_set=['get_n_peer_links'])
        pcb.get_n_peer_links.return_value = 1
        ntools.assert_true(pth_pol._check_property_ranges(pcb))
        pcb.get_n_peer_links.assert_called_once_with()

    def test_peer_link_false(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d
        pth_pol.property_ranges['PeerLinks'].extend([0, 2])
        pcb = MagicMock(spec_set=['get_n_peer_links'])
        pcb.get_n_peer_links.return_value = 3
        ntools.assert_false(pth_pol._check_property_ranges(pcb))

    def test_hop_length_true(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d
        pth_pol.property_ranges['HopsLength'].extend([0, 2])
        pcb = MagicMock(spec_set=['get_n_hops'])
        pcb.get_n_hops.return_value = 1
        ntools.assert_true(pth_pol._check_property_ranges(pcb))
        pcb.get_n_hops.assert_called_once_with()

    def test_hop_length_false(self):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d
        pth_pol.property_ranges['HopsLength'].extend([0, 2])
        pcb = MagicMock(spec_set=['get_n_hops'])
        pcb.get_n_hops.return_value = 3
        ntools.assert_false(pth_pol._check_property_ranges(pcb))

    @patch("lib.path_store.SCIONTime.get_time", spec_set=[],
           new_callable=MagicMock)
    def test_delay_time_true(self, time_):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d
        pth_pol.property_ranges['DelayTime'].extend([0, 2])
        time_.return_value = 2
        pcb = MagicMock(spec_set=['get_timestamp'])
        pcb.get_timestamp.return_value = 1
        ntools.assert_true(pth_pol._check_property_ranges(pcb))
        time_.assert_called_once_with()
        pcb.get_timestamp.assert_called_once_with()

    @patch("lib.path_store.SCIONTime.get_time", spec_set=[],
           new_callable=MagicMock)
    def test_delay_time_false(self, time_):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d
        pth_pol.property_ranges['DelayTime'].extend([0, 2])
        time_.return_value = 2
        pcb = MagicMock(spec_set=['get_timestamp'])
        pcb.get_timestamp.return_value = 3
        ntools.assert_false(pth_pol._check_property_ranges(pcb))

    def _check_bandwidth(self, key, range_, result):
        pth_pol = PathPolicy()
        pth_pol.property_ranges = self.d
        pth_pol.property_ranges[key].extend(range_)
        ntools.eq_(pth_pol._check_property_ranges("pcb"), result)

    def test_bandwidth(self):
        for key in ('GuaranteedBandwidth', 'AvailableBandwidth',
                    'TotalBandwidth'):
            yield self._check_bandwidth, key, [0, 20], True
            yield self._check_bandwidth, key, [0, 9], False


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

    @patch("lib.path_store.logging.error", autospec=True)
    def _check_error(self, key, error_):
        with patch('lib.path_store.open', mock_open(), create=True) as open_f:
            open_f.side_effect = key
            ntools.assert_is_none(PathPolicy.from_file("policy_file"))
            ntools.eq_(error_.call_count, 1)

    def test_error(self):
        for key in (ValueError, KeyError, TypeError):
            yield self._check_error, key


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
        ntools.eq_(pth_pol2.property_ranges, {'key1': (1, 11), 'key2': (2, 12)})
        ntools.eq_(pth_pol2.property_weights, "property_weights")


class TestPathStoreRecordInit(object):
    """
    Unit tests for lib.path_store.PathStoreRecord.__init__
    """
    @patch("lib.path_store.SCIONTime.get_time", spec_set=[],
           new_callable=MagicMock)
    def test_basic(self, time_):
        pcb = MagicMock(spec_set=['__class__', 'segment_id',
                                  'get_expiration_time', 'get_hops_hash'])
        pcb.__class__ = PathSegment
        pcb.segment_id = "id"
        pcb.get_expiration_time.return_value = "get_expiration_time"
        time_.return_value = 23
        pth_str_rec = PathStoreRecord(pcb)
        ntools.eq_(pth_str_rec.pcb, pcb)
        ntools.eq_(pth_str_rec.id, pcb.get_hops_hash())
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
    @patch("lib.path_store.SCIONTime.get_time", spec_set=[],
           new_callable=MagicMock)
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
                                  'get_expiration_time', 'get_hops_hash'])
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
    def setUp(self):
        self.pcb = MagicMock(spec_set=['__class__', 'segment_id',
                                       'get_expiration_time', 'get_hops_hash'])
        self.pcb.__class__ = PathSegment

    def tearDown(self):
        del self.pcb

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


class TestPathStoreInit(object):
    """
    Unit tests for lib.path_store.PathStore.__init__
    """
    @patch("lib.path_store.deque", autospec=True)
    def test_basic(self, deque_):
        path_policy = MagicMock(spec_set=['history_limit'])
        path_policy.history_limit = 3
        deque_.return_value = "best_paths_history"
        pth_str = PathStore(path_policy)
        ntools.eq_(pth_str.path_policy, path_policy)
        ntools.eq_(pth_str.candidates, [])
        deque_.assert_called_once_with(maxlen=3)
        ntools.eq_(pth_str.best_paths_history, "best_paths_history")


class TestPathStoreAddSegment(object):
    """
    Unit tests for lib.path_store.PathStore.add_segment
    """
    def setUp(self):
        self.pcb = MagicMock(spec_set=PathSegment)

    def tearDown(self):
        del self.pcb

    def test_filters(self):
        path_policy = MagicMock(spec_set=['history_limit', 'check_filters'])
        path_policy.history_limit = 3
        path_policy.check_filters.return_value = False
        pth_str = PathStore(path_policy)
        pth_str.add_segment(self.pcb)
        path_policy.check_filters.assert_called_once_with(self.pcb)

    @patch("lib.path_store.PathStoreRecord", autospec=True)
    def test_basic(self, pth_str_rec):
        path_policy = MagicMock(spec_set=['history_limit', 'check_filters',
                                          'candidates_set_size'])
        path_policy.history_limit = 3
        path_policy.candidates_set_size = 7
        record = MagicMock(spec_set=['last_sent_time', 'fidelity'])
        record.last_sent_time = 7
        record.fidelity = 7
        pth_str_rec.return_value = record
        pth_str = PathStore(path_policy)
        pth_str.candidates = [MagicMock(spec_set=['last_sent_time', '__eq__',
                                                  'fidelity'])
                              for i in range(5)]
        for i in range(5):
            pth_str.candidates[i].last_sent_time = i
            pth_str.candidates[i].fidelity = i
        pth_str.candidates[4].__eq__.return_value = True
        pth_str._update_all_fidelity = MagicMock(spec_set=[])
        pth_str.add_segment(self.pcb)
        pth_str._update_all_fidelity.assert_called_once_with()
        ntools.eq_(len(pth_str.candidates), 5)
        ntools.eq_(pth_str.candidates[0], record)
        for i in range(1, 5):
            ntools.eq_(pth_str.candidates[i].last_sent_time, 4 - i)

    @patch("lib.path_store.PathStoreRecord", autospec=True)
    def test_removal(self, pth_str_rec):
        path_policy = MagicMock(spec_set=['history_limit', 'check_filters',
                                          'candidates_set_size',
                                          'best_set_size'])
        path_policy.history_limit = 3
        path_policy.candidates_set_size = 3
        path_policy.best_set_size = 3
        record = MagicMock(spec_set=['fidelity'])
        record.fidelity = 7
        pth_str_rec.return_value = record
        pth_str = PathStore(path_policy)
        pth_str.candidates = [MagicMock(spec_set=['fidelity'])
                              for i in range(5)]
        for i in range(5):
            pth_str.candidates[i].fidelity = i
        pth_str._update_all_fidelity = MagicMock(spec_set=[])
        pth_str._remove_expired_segments = MagicMock(spec_set=[])
        pth_str.best_paths_history = MagicMock(spec_set=['appendleft'])
        pth_str.add_segment(self.pcb)
        pth_str._remove_expired_segments.assert_called_once_with()
        ntools.eq_(len(pth_str.candidates), 3)
        pth_str.best_paths_history.appendleft.assert_called_once_with(
            pth_str.candidates)


class TestPathStoreUpdateAllPeerLinks(object):
    """
    Unit tests for lib.path_store._update_all_peer_links
    """
    def test_basic(self):
        path_policy = MagicMock(spec_set=['history_limit'])
        path_policy.history_limit = 3
        pth_str = PathStore(path_policy)
        pth_str.candidates = [MagicMock(spec_set=['pcb', 'peer_links'])
                              for i in range(5)]
        for i in range(5):
            pcb = MagicMock(spec_set=['get_n_peer_links'])
            pcb.get_n_peer_links.return_value = 2*i + 1
            pth_str.candidates[i].pcb = pcb
        pth_str._update_all_peer_links()
        for i in range(5):
            pth_str.candidates[i].pcb.get_n_peer_links.assert_called_once_with()
            ntools.assert_almost_equal(pth_str.candidates[i].peer_links,
                                       ((2 * i + 1) / 10))


class TestPathStoreUpdateAllHopsLength(object):
    """
    Unit tests for lib.path_store._update_all_hops_length
    """
    def test_basic(self):
        path_policy = MagicMock(spec_set=['history_limit'])
        path_policy.history_limit = 3
        pth_str = PathStore(path_policy)
        pth_str.candidates = [MagicMock(spec_set=['pcb', 'hops_length'])
                              for i in range(5)]
        for i in range(5):
            pcb = MagicMock(spec_set=['get_n_hops'])
            pcb.get_n_hops.return_value = 2*i + 2
            pth_str.candidates[i].pcb = pcb
        pth_str._update_all_hops_length()
        for i in range(5):
            pth_str.candidates[i].pcb.get_n_hops.assert_called_once_with()
            ntools.assert_almost_equal(pth_str.candidates[i].hops_length,
                                       ((2 * i + 2) / 10))


class TestPathStoreUpdateAllDisjointness(object):
    """
    Unit tests for lib.path_store._update_all_disjointness
    """
    def test_basic(self):
        path_policy = MagicMock(spec_set=['history_limit'])
        path_policy.history_limit = 3
        pth_str = PathStore(path_policy)
        pth_str.candidates = [MagicMock(spec_set=['pcb', 'disjointness'])
                              for i in range(5)]
        for i in range(5):
            pcb = MagicMock(spec_set=['ads'])
            pcb.ads = [MagicMock(spec_set=['pcbm']) for j in range(5)]
            for j in range(5):
                pcbm = MagicMock(spec_set=['ad_id'])
                pcbm.ad_id = i * 5 + j
                pcb.ads[j].pcbm = pcbm
            pth_str.candidates[i].pcb = pcb
        pth_str._update_all_disjointness()
        for i in range(5):
            ntools.assert_almost_equal(pth_str.candidates[i].disjointness,
                                       (20 / 25))


class TestPathStoreUpdateAllDelayTime(object):
    """
    Unit tests for lib.path_store._update_all_delay_time
    """
    def test_basic(self):
        path_policy = MagicMock(spec_set=['history_limit'])
        path_policy.history_limit = 3
        pth_str = PathStore(path_policy)
        pth_str.candidates = [MagicMock(spec_set=['pcb', 'delay_time',
                                                  'last_seen_time'])
                              for i in range(5)]
        for i in range(5):
            pcb = MagicMock(spec_set=['get_timestamp'])
            pcb.get_timestamp.return_value = 1
            pth_str.candidates[i].pcb = pcb
            pth_str.candidates[i].last_seen_time = 2 * i + 2
        pth_str._update_all_delay_time()
        for i in range(5):
            pth_str.candidates[i].pcb.get_timestamp.assert_called_once_with()
            ntools.assert_almost_equal(pth_str.candidates[i].delay_time,
                                       ((2 * i + 2) / 10))


class TestPathStoreUpdateAllFidelity(object):
    """
    Unit tests for lib.path_store._update_all_fidelity
    """
    def test_basic(self):
        path_policy = MagicMock(spec_set=['history_limit'])
        path_policy.history_limit = 3
        pth_str = PathStore(path_policy)
        pth_str._update_all_peer_links = MagicMock(spec_set=[])
        pth_str._update_all_hops_length = MagicMock(spec_set=[])
        pth_str._update_all_disjointness = MagicMock(spec_set=[])
        pth_str._update_all_delay_time = MagicMock(spec_set=[])
        pth_str.candidates = [MagicMock(spec_set=['update_fidelity'])
                              for i in range(5)]
        pth_str._update_all_fidelity()
        pth_str._update_all_peer_links.assert_called_once_with()
        pth_str._update_all_hops_length.assert_called_once_with()
        pth_str._update_all_disjointness.assert_called_once_with()
        pth_str._update_all_delay_time.assert_called_once_with()
        for i in range(5):
            pth_str.candidates[i].update_fidelity.assert_called_once_with(
                path_policy)


class TestPathStoreGetBestSegments(object):
    """
    Unit tests for lib.path_store.get_best_segments
    """
    def test_basic(self):
        path_policy = MagicMock(spec_set=['history_limit'])
        path_policy.history_limit = 3
        pth_str = PathStore(path_policy)
        pth_str._remove_expired_segments = MagicMock(spec_set=[])
        pth_str.candidates = [MagicMock(spec_set=['pcb']) for i in range(5)]
        for i in range(5):
            pth_str.candidates[i].pcb = i
        ntools.eq_(pth_str.get_best_segments(3), [0, 1, 2])
        pth_str._remove_expired_segments.assert_called_once_with()

    def test_less_arg(basic):
        path_policy = MagicMock(spec_set=['history_limit', 'best_set_size'])
        path_policy.history_limit = 3
        path_policy.best_set_size = 4
        pth_str = PathStore(path_policy)
        pth_str._remove_expired_segments = MagicMock(spec_set=[])
        pth_str.candidates = [MagicMock(spec_set=['pcb']) for i in range(5)]
        for i in range(5):
            pth_str.candidates[i].pcb = i
        ntools.eq_(pth_str.get_best_segments(), [0, 1, 2, 3])


class TestPathStoreGetLatestHistorySnapshot(object):
    """
    Unit tests for lib.path_store.get_latest_history_snapshot
    """
    def _setup(self, attrs=None):
        def_attrs = {'history_limit': 3}
        if attrs:
            def_attrs.update(attrs)
        path_policy = MagicMock(spec_set=list(def_attrs.keys()))
        path_policy.history_limit = 3
        for k, v in def_attrs.items():
            setattr(path_policy, k, v)
        return path_policy

    def test_basic(self):
        pth_str = PathStore(self._setup())
        pth_str.best_paths_history = []
        pth_str.best_paths_history.append([MagicMock(spec_set=['pcb'])
                                           for i in range(5)])
        for i in range(5):
            pth_str.best_paths_history[0][i].pcb = i
        ntools.eq_(pth_str.get_latest_history_snapshot(3), [0, 1, 2])

    def test_less_arg(self):
        pth_str = PathStore(self._setup({'best_set_size': 4}))
        pth_str.best_paths_history = []
        pth_str.best_paths_history.append([MagicMock(spec_set=['pcb'])
                                           for i in range(5)])
        for i in range(5):
            pth_str.best_paths_history[0][i].pcb = i
        ntools.eq_(pth_str.get_latest_history_snapshot(), [0, 1, 2, 3])

    def test_false(self):
        pth_str = PathStore(self._setup())
        ntools.eq_(pth_str.get_latest_history_snapshot(3), [])


class TestPathStoreRemoveExpiredSegments(object):
    """
    Unit tests for lib.path_store._remove_expired_segments
    """
    @patch("lib.path_store.SCIONTime.get_time", spec_set=[],
           new_callable=MagicMock)
    def test_basic(self, time_):
        path_policy = MagicMock(spec_set=['history_limit'])
        path_policy.history_limit = 3
        pth_str = PathStore(path_policy)
        pth_str.candidates = [MagicMock(spec_set=['expiration_time', 'id'])
                              for i in range(5)]
        for i in range(5):
            pth_str.candidates[i].expiration_time = i
            pth_str.candidates[i].id = i
        time_.return_value = 2
        pth_str.remove_segments = MagicMock(spec_set=[])
        pth_str._remove_expired_segments()
        pth_str.remove_segments.assert_called_once_with([0, 1, 2])


class TestPathStoreRemoveSegments(object):
    """
    Unit tests for lib.path_store.remove_segments
    """
    def setUp(self):
        self.path_policy = MagicMock(spec_set=['history_limit'])
        self.path_policy.history_limit = 3

    def tearDown(self):
        del self.path_policy

    def test_basic(self):
        pth_str = PathStore(self.path_policy)
        pth_str.candidates = [MagicMock(spec_set=['id', 'fidelity'])
                              for i in range(5)]
        for i in range(5):
            pth_str.candidates[i].id = i
            pth_str.candidates[i].fidelity = i
        pth_str._update_all_fidelity = MagicMock(spec_set=[])
        pth_str.remove_segments([1, 2, 3])
        ntools.eq_(len(pth_str.candidates), 2)
        ntools.eq_(pth_str.candidates[0].id, 4)
        ntools.eq_(pth_str.candidates[1].id, 0)
        pth_str._update_all_fidelity.assert_called_once_with()

    def test_none(self):
        pth_str = PathStore(self.path_policy)
        pth_str.candidates = [MagicMock(spec_set=['id']) for i in range(5)]
        for i in range(5):
            pth_str.candidates[i].id = i
        pth_str.remove_segments([0, 1, 2, 3, 4])
        ntools.eq_(pth_str.candidates, [])


class TestPathStoreGetSegment(object):
    """
    Unit tests for lib.path_store.get_segment
    """
    def setUp(self):
        self.path_policy = MagicMock(spec_set=['history_limit'])
        self.path_policy.history_limit = 3

    def tearDown(self):
        del self.path_policy

    def test_basic(self):
        pth_str = PathStore(self.path_policy)
        pth_str.candidates = [MagicMock(spec_set=['id', 'pcb'])
                              for i in range(5)]
        for i in range(5):
            pth_str.candidates[i].id = i
            pth_str.candidates[i].pcb = i
        ntools.eq_(pth_str.get_segment(2), 2)

    def test_not_present(self):
        pth_str = PathStore(self.path_policy)
        pth_str.candidates = [MagicMock(spec_set=['id']) for i in range(5)]
        ntools.assert_is_none(pth_str.get_segment(2))

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
