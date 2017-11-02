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
from lib.errors import SCIONPathPolicyViolated
from lib.packet.pcb import PathSegment
from lib.path_store import (
    PathPolicy,
    PathStore,
    PathStoreRecord
)
from test.testcommon import create_mock, create_mock_full


class TestPathPolicyCheckFilters(object):
    """
    Unit tests for lib.path_store.PathPolicy.check_filters
    """
    def _setup(self, unwanted=None, reasons=None, remote_ia=None):
        inst = PathPolicy()
        inst._check_unwanted_ases = create_mock()
        inst._check_unwanted_ases.return_value = unwanted
        inst._check_property_ranges = create_mock()
        inst._check_property_ranges.return_value = reasons
        inst._check_remote_ifid = create_mock()
        inst._check_remote_ifid.return_value = remote_ia
        pcb = create_mock(["short_desc"], class_=PathSegment)
        return inst, pcb

    def test_basic(self):
        inst, pcb = self._setup()
        # Call
        inst.check_filters(pcb)

    def test_unwanted_ases(self):
        inst, pcb = self._setup("unwanted AS")
        # Call
        ntools.assert_raises(SCIONPathPolicyViolated, inst.check_filters, pcb)

    def test_property_ranges(self):
        inst, pcb = self._setup(reasons="reasons")
        ntools.assert_raises(SCIONPathPolicyViolated, inst.check_filters, pcb)


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
    @patch("lib.path_store.SCIONTime.get_time", new_callable=create_mock)
    @patch("lib.path_store.PathStoreRecord.__init__", autospec=True,
           return_value=None)
    def test(self, init, get_time):
        inst = PathStoreRecord("pcb")
        get_time.return_value = 100
        pcb = create_mock(["copy", "get_hops_hash", "get_timestamp",
                           "get_expiration_time"])
        inst.id = pcb.get_hops_hash.return_value
        pcb.get_timestamp.return_value = 95
        # Call
        inst.update(pcb)
        # Tests
        pcb.copy.assert_called_once_with()
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


class TestPathStoreAddSegment(object):
    """
    Unit tests for lib.path_store.PathStore.add_segment
    """
    def _setup(self, filter_=True):
        inst = PathStore("path_policy")
        inst.path_policy = create_mock(["check_filters"])
        if not filter_:
            inst.path_policy.check_filters.side_effect = SCIONPathPolicyViolated()
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
        inst = PathStore(create_mock_full({'history_limit': 3}))
        numCandidates = 5
        pathLength = 5
        inst.candidates = []
        inst.disjointness = {}
        for i in range(numCandidates):
            id_ = i * (2 * pathLength + 1)
            asms = []
            for j in range(pathLength):
                isdas = 9, id_ + j + 1
                hof = create_mock_full({'egress_if': isdas[1] + pathLength})
                pcbm = create_mock_full({'hof()': hof})
                asms.append(create_mock_full({
                    "isd_as()": isdas, "pcbm()": pcbm}))
                inst.disjointness[isdas[1]] = 1.0
                inst.disjointness[hof.egress_if] = 1.0
            pcb = create_mock_full({"iter_asms()": asms})
            record = create_mock_full(
                {'pcb': pcb, 'disjointness': 0, 'id': id_})
            inst.disjointness[id_] = 1.0
            inst.candidates.append(record)
        inst._update_disjointness_db = create_mock()
        inst._update_all_disjointness()
        for i in range(numCandidates):
            ntools.assert_almost_equal(inst.candidates[i].disjointness, 1.0)


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
