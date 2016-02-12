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
import math
from unittest.mock import patch, MagicMock

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
from test.testcommon import create_mock


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
        ntools.eq_(pth_pol.unwanted_ases, [])
        ntools.eq_(pth_pol.property_ranges, {})
        ntools.eq_(pth_pol.property_weights, {})


class TestPathPolicyGetPathPolicyDict(object):
    """
    Unit tests for lib.path_store.PathPolicy.get_path_policy_dict
    """
    def test_basic(self):
        keys = ["best_set_size", "candidates_set_size", "history_limit",
                "update_after_number", "update_after_time", "unwanted_ases",
                "property_ranges", "property_weights"]
        pth_pol = PathPolicy()
        target = {}
        for key in keys:
            setattr(pth_pol, key, key)
            target[key] = key
        dict_ = pth_pol.get_path_policy_dict()
        ntools.eq_(dict_, target)


class TestPathPolicyCheckFilters(object):
    """
    Unit tests for lib.path_store.PathPolicy.check_filters
    """
    def _setup(self, unwanted=None, reasons=None):
        inst = PathPolicy()
        inst._check_unwanted_ases = create_mock()
        inst._check_unwanted_ases.return_value = unwanted
        inst._check_property_ranges = create_mock()
        inst._check_property_ranges.return_value = reasons
        pcb = create_mock(["short_desc"], class_=PathSegment)
        return inst, pcb

    def test_basic(self):
        inst, pcb = self._setup()
        # Call
        ntools.assert_true(inst.check_filters(pcb))

    def test_unwanted_ases(self):
        inst, pcb = self._setup("unwanted AS")
        # Call
        ntools.assert_false(inst.check_filters(pcb))

    def test_property_ranges(self):
        inst, pcb = self._setup(reasons="reasons")
        ntools.assert_false(inst.check_filters(pcb))


class TestPathPolicyCheckUnwantedASes(object):
    """
    Unit tests for lib.path_store.PathPolicy._check_unwanted_ases
    """
    def _setup(self):
        inst = PathPolicy()
        pcb = create_mock(['ases'])
        pcb.ases = []
        for i in range(5):
            asm = create_mock(['pcbm'])
            asm.pcbm = create_mock(['isd_as'])
            asm.pcbm.isd_as = "%d-%d" % (i, i)
            pcb.ases.append(asm)
        return inst, pcb

    def test_basic(self):
        inst, pcb = self._setup()
        unwanted = "2-2"
        inst.unwanted_ases = [unwanted]
        # Call
        ntools.eq_(inst._check_unwanted_ases(pcb), unwanted)

    def test_not_present(self):
        inst, pcb = self._setup()
        ntools.assert_is_none(inst._check_unwanted_ases(pcb))


class TestPathPolicyCheckPropertyRanges(object):
    """
    Unit tests for lib.path_store.PathPolicy._check_property_ranges
    """
    def _setup(self, max_bw=20):
        inst = PathPolicy()
        inst.property_ranges = {
            'PeerLinks': [0, 1], 'HopsLength': [0, 1], 'DelayTime': [0, 1],
            'GuaranteedBandwidth': [0, max_bw],
            'AvailableBandwidth': [0, max_bw], 'TotalBandwidth': [0, max_bw]
        }
        pcb = create_mock(["get_n_peer_links", "get_n_hops", "get_timestamp"])
        return inst, pcb

    @patch("lib.path_store.SCIONTime.get_time", new_callable=create_mock)
    def test_success(self, get_time):
        inst, pcb = self._setup()
        pcb.get_n_peer_links.return_value = 0.5
        pcb.get_n_hops.return_value = 0.5
        pcb.get_timestamp.return_value = 0.5
        # Call
        ntools.eq_(inst._check_property_ranges(pcb), [])

    @patch("lib.path_store.SCIONTime.get_time", new_callable=create_mock)
    def test_failure(self, get_time):
        inst, pcb = self._setup(max_bw=9)
        pcb.get_n_peer_links.return_value = 2
        pcb.get_n_hops.return_value = -1
        pcb.get_timestamp.return_value = -0.1
        # Call
        ntools.eq_(len(inst._check_property_ranges(pcb)), 6)

    @patch("lib.path_store.SCIONTime.get_time", new_callable=create_mock)
    def test_no_checks(self, get_time):
        inst, pcb = self._setup(max_bw=9)
        for key in inst.property_ranges:
            inst.property_ranges[key] = []
        pcb.get_n_peer_links.return_value = 2
        pcb.get_n_hops.return_value = -1
        pcb.get_timestamp.return_value = -0.1
        # Call
        ntools.eq_(inst._check_property_ranges(pcb), [])


class TestPathPolicyFromFile(object):
    """
    Unit tests for lib.path_store.PathPolicy.from_file
    """
    @patch("lib.path_store.PathPolicy.from_dict", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.path_store.load_yaml_file", autospec=True)
    def test_basic(self, load, from_dict):
        load.return_value = "policy_dict"
        from_dict.return_value = "from_dict"
        ntools.eq_(PathPolicy.from_file("policy_file"), "from_dict")
        load.assert_called_once_with("policy_file")
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
        dict_['UnwantedASes'] = "1-11,2-12"
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
    @patch("lib.path_store.PathStoreRecord.update", autospec=True)
    @patch("lib.path_store.SCIONTime.get_time", new_callable=create_mock)
    def test(self, get_time, update):
        pcb = create_mock(['get_hops_hash', 'get_n_hops', 'get_n_peer_links'],
                          class_=PathSegment)
        get_time.return_value = PathStoreRecord.DEFAULT_OFFSET + 1
        # Call
        inst = PathStoreRecord(pcb)
        # Tests
        ntools.eq_(inst.id, pcb.get_hops_hash.return_value)
        ntools.eq_(inst.peer_links, pcb.get_n_peer_links.return_value)
        ntools.eq_(inst.hops_length, pcb.get_n_hops.return_value)
        ntools.eq_(inst.fidelity, 0)
        ntools.eq_(inst.disjointness, 0)
        ntools.eq_(inst.last_sent_time, 1)
        ntools.eq_(inst.guaranteed_bandwidth, 0)
        ntools.eq_(inst.available_bandwidth, 0)
        ntools.eq_(inst.total_bandwidth, 0)
        update.assert_called_once_with(inst, pcb)


class TestPathStoreRecordUpdate(object):
    """
    Unit tests for lib.path_store.PathStoreRecord.update
    """
    @patch("lib.path_store.copy.deepcopy", autospec=True)
    @patch("lib.path_store.SCIONTime.get_time", new_callable=create_mock)
    @patch("lib.path_store.PathStoreRecord.__init__", autospec=True,
           return_value=None)
    def test(self, init, get_time, deepcopy):
        inst = PathStoreRecord("pcb")
        get_time.return_value = 100
        pcb = create_mock(["get_hops_hash", "get_timestamp",
                           "get_expiration_time"])
        inst.id = pcb.get_hops_hash.return_value
        pcb.get_timestamp.return_value = 95
        # Call
        inst.update(pcb)
        # Tests
        deepcopy.assert_called_once_with(pcb)
        ntools.eq_(inst.pcb, deepcopy.return_value)
        ntools.eq_(inst.delay_time, 5)
        ntools.eq_(inst.last_seen_time, 100)
        ntools.eq_(inst.expiration_time, pcb.get_expiration_time.return_value)


class TestPathStoreRecordUpdateFidelity(object):
    """
    Unit tests for lib.path_store.PathStoreRecord.update_fidelity
    """
    @patch("lib.path_store.SCIONTime.get_time", new_callable=create_mock)
    @patch("lib.path_store.PathStoreRecord.__init__", autospec=True,
           return_value=None)
    def test_basic(self, init, time_):
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
        pth_str_rec = PathStoreRecord("pcb")
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


class TestPathStoreInit(object):
    """
    Unit tests for lib.path_store.PathStore.__init__
    """
    @patch("lib.path_store.defaultdict", autospec=True)
    @patch("lib.path_store.deque", autospec=True)
    def test_basic(self, deque_, defaultdict_):
        path_policy = MagicMock(spec_set=['history_limit'])
        path_policy.history_limit = 3
        deque_.return_value = "best_paths_history"
        pth_str = PathStore(path_policy)
        ntools.eq_(pth_str.path_policy, path_policy)
        ntools.eq_(pth_str.candidates, [])
        deque_.assert_called_once_with(maxlen=3)
        ntools.eq_(pth_str.best_paths_history, "best_paths_history")
        defaultdict_.assert_called_once_with(float)
        ntools.eq_(pth_str.last_dj_update, 0)


class TestPathStoreAddSegment(object):
    """
    Unit tests for lib.path_store.PathStore.add_segment
    """
    def _setup(self, filter_=True):
        inst = PathStore("path_policy")
        inst.path_policy = create_mock(["check_filters"])
        inst.path_policy.check_filters.return_value = filter_
        pcb = create_mock(["get_hops_hash", "get_timestamp"],
                          class_=PathSegment)
        return inst, pcb

    @patch("lib.path_store.PathStore.__init__", autospec=True,
           return_value=None)
    def test_filters(self, psi):
        """
        Try to add a path that does not meet the filter requirements.
        """
        inst, pcb = self._setup(filter_=False)
        # Call
        inst.add_segment(pcb)
        # Tests
        inst.path_policy.check_filters.assert_called_once_with(pcb)

    @patch("lib.path_store.PathStore.__init__", autospec=True,
           return_value=None)
    def test_already_in_store(self, init):
        """
        Try to add a path that is already in the path store.
        """
        inst, pcb = self._setup()
        candidate = create_mock(['id', 'update'])
        candidate.id = pcb.get_hops_hash.return_value
        inst.candidates = [candidate]
        # Call
        inst.add_segment(pcb)
        # Tests
        candidate.update.assert_called_once_with(pcb)

    @patch("lib.path_store.PathStoreRecord", autospec=True)
    @patch("lib.path_store.PathStore.__init__", autospec=True,
           return_value=None)
    def test_adding(self, psi, psr):
        """
        Add a single path segment to the set of candidate paths.
        """
        inst, pcb = self._setup()
        inst.candidates = []
        inst._trim_candidates = create_mock()
        # Call
        inst.add_segment(pcb)
        # Tests
        ntools.eq_(inst.candidates, [psr.return_value])
        inst._trim_candidates.assert_called_once_with()


class TestPathStoreTrimCandidates(object):
    """
    Unit tests for lib.path_store.PathStore._trim_candidates
    """

    @patch("lib.path_store.PathStore.__init__", autospec=True,
           return_value=None)
    def test_expire_paths(self, psi):
        """
        Test trimming the size of the candidate set by removing an expired
        segment.
        """
        pth_str = PathStore("path_policy")
        pth_str.path_policy = MagicMock(spec_set=['candidates_set_size'])
        pth_str.path_policy.candidates_set_size = 0
        pth_str.candidates = [0]
        pth_str._remove_expired_segments = (
            lambda: pth_str.candidates.pop())
        pth_str._trim_candidates()
        ntools.eq_(pth_str.candidates, [])

    @patch("lib.path_store.PathStore.__init__", autospec=True,
           return_value=None)
    def test_remove_low_fidelity_path(self, psi):
        """
        Add a path, find that the candidate set size is too large, and remove
        the lowest-fidelity path.
        """
        pth_str = PathStore("path_policy")
        pth_str.path_policy = MagicMock(spec_set=['candidates_set_size'])
        pth_str.path_policy.candidates_set_size = 2
        pth_str.candidates = [create_mock(['fidelity']) for i in range(3)]
        pth_str.candidates[0].fidelity = 2
        pth_str.candidates[1].fidelity = 0
        pth_str.candidates[2].fidelity = 1
        remainder = [pth_str.candidates[0], pth_str.candidates[2]]
        pth_str._remove_expired_segments = create_mock()
        pth_str._update_all_fidelity = create_mock()
        pth_str._trim_candidates()
        pth_str._remove_expired_segments.assert_called_once_with()
        pth_str._update_all_fidelity.assert_called_once_with()
        ntools.eq_(pth_str.candidates, remainder)


class TestPathStoreUpdateDisjointnessDB(object):
    """
    Unit tests for lib.path_store._update_disjointness_db
    """
    @patch("lib.path_store.SCIONTime.get_time", spec_set=[],
           new_callable=MagicMock)
    def test_basic(self, time_):
        path_policy = MagicMock(spec_set=['history_limit'])
        path_policy.history_limit = 3
        pth_str = PathStore(path_policy)
        pth_str.disjointness = {0: math.e, 1: math.e**2}
        pth_str.last_dj_update = 22
        time_.return_value = 23
        pth_str._update_disjointness_db()
        ntools.eq_(pth_str.last_dj_update, time_.return_value)
        ntools.assert_almost_equal(pth_str.disjointness[0], 1.0)
        ntools.assert_almost_equal(pth_str.disjointness[1], math.e)


class TestPathStoreUpdateAllDisjointness(object):
    """
    Unit tests for lib.path_store._update_all_disjointness
    """
    def test(self):
        path_policy = MagicMock(spec_set=['history_limit'])
        path_policy.history_limit = 3
        pth_str = PathStore(path_policy)
        numCandidates = 5
        pathLength = 5
        pth_str.candidates = []
        pth_str.disjointness = {}
        for i in range(numCandidates):
            record = create_mock(['pcb', 'disjointness', 'id'])
            record.id = i * (2 * pathLength + 1)
            pth_str.disjointness[record.id] = 1.0
            record.pcb = create_mock(['ases'])
            record.pcb.ases = []
            for j in range(pathLength):
                pcbm = create_mock(['isd_as', 'hof'])
                pcbm.isd_as = (9, record.id + j + 1)
                pth_str.disjointness[pcbm.isd_as[1]] = 1.0
                pcbm.hof = MagicMock(spec_set=['egress_if'])
                pcbm.hof.egress_if = pcbm.isd_as[1] + pathLength
                pth_str.disjointness[pcbm.hof.egress_if] = 1.0
                as_marking = create_mock(['pcbm'])
                as_marking.pcbm = pcbm
                record.pcb.ases.append(as_marking)
            pth_str.candidates.append(record)
        pth_str._update_disjointness_db = create_mock()
        pth_str._update_all_disjointness()
        for i in range(numCandidates):
            ntools.assert_almost_equal(pth_str.candidates[i].disjointness,
                                       1.0)


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
        pth_str._update_all_disjointness = MagicMock(spec_set=[])
        pth_str._update_all_delay_time = MagicMock(spec_set=[])
        pth_str.candidates = [MagicMock(spec_set=['update_fidelity'])
                              for i in range(5)]
        pth_str._update_all_fidelity()
        pth_str._update_all_disjointness.assert_called_once_with()
        pth_str._update_all_delay_time.assert_called_once_with()
        for i in range(5):
            pth_str.candidates[i].update_fidelity.assert_called_once_with(
                path_policy)


class TestPathStoreGetBestSegments(object):
    """
    Unit tests for lib.path_store.PathStore.get_best_segments
    """
    def _setup(self):
        inst = PathStore("path_policy")
        inst._remove_expired_segments = create_mock()
        inst._update_all_fidelity = create_mock()
        inst.candidates = []
        for i, fidelity in enumerate([0, 5, 2, 6, 3]):
            candidate = create_mock(["pcb", "fidelity", "sending"])
            candidate.pcb = "pcb%d" % i
            candidate.fidelity = fidelity
            inst.candidates.append(candidate)
        return inst

    @patch("lib.path_store.PathStore.__init__", autospec=True,
           return_value=None)
    def test_full(self, init):
        inst = self._setup()
        # Call
        ntools.eq_(inst.get_best_segments(k=3, sending=False),
                   ["pcb3", "pcb1", "pcb4"])
        # Tests
        inst._remove_expired_segments.assert_called_once_with()
        inst._update_all_fidelity.assert_called_once_with()
        for i in inst.candidates:
            ntools.assert_false(i.sending.called)

    @patch("lib.path_store.PathStore.__init__", autospec=True,
           return_value=None)
    def test_less_arg(self, init):
        inst = self._setup()
        inst.path_policy = create_mock(["best_set_size"])
        inst.path_policy.best_set_size = 1
        # Call
        ntools.eq_(inst.get_best_segments(), ["pcb3"])
        # Tests
        for i in inst.candidates:
            if i.fidelity == 6:
                i.sending.assert_called_once_with()
            else:
                ntools.assert_false(i.sending.called)


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
