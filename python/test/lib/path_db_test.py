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
:mod:`lib_path_db_test` --- lib.path_db tests
=====================================================
"""
# Stdlib
from unittest.mock import patch, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.pcb import PathSegment
from lib.path_db import (
    DBResult,
    PathSegmentDB,
    PathSegmentDBRecord
)
from test.testcommon import assert_these_calls, create_mock, create_mock_full


class TestPathSegmentDBRecordInit(object):
    """
    Unit tests for lib.path_db.PathSegmentDBRecord.__init__
    """
    def test(self):
        pcb = create_mock_full({
            'get_hops_hash()': "hash", "get_n_hops()": 42,
            "get_expiration_time()": 71}, class_=PathSegment)
        # Call
        inst = PathSegmentDBRecord(pcb)
        # Tests
        ntools.eq_(inst.pcb, pcb)
        ntools.eq_(inst.id, "hash")
        ntools.eq_(inst.fidelity, 42)
        ntools.eq_(inst.exp_time, 71)


class TestPathSegmentDBUpdate(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.update
    """
    def _mk_pcb(self, exp=0):
        return create_mock_full({
            'get_hops_hash()': "hash", "get_n_hops()": 42,
            "get_expiration_time()": exp, "first_ia()": (1, 2),
            "last_ia()": (3, 4), "is_sibra()": True, "short_desc()": "short",
        })

    @patch("lib.path_db.PathSegmentDBRecord", autospec=True)
    def test_add(self, db_rec):
        inst = PathSegmentDB()
        inst._db = create_mock_full({'insert()': None}, return_value=[])
        pcb = self._mk_pcb()
        record = create_mock_full({'id': "id str"})
        db_rec.return_value = record
        # Call
        ntools.eq_(inst.update(pcb), DBResult.ENTRY_ADDED)
        # Tests
        db_rec.assert_called_once_with(pcb)
        inst._db.assert_called_once_with(id="id str", sibra=True)
        inst._db.insert.assert_called_once_with(record, "id str", 1, 2, 3, 4,
                                                True)

    @patch("lib.path_db.PathSegmentDBRecord", autospec=True)
    def test_outdated(self, db_rec):
        inst = PathSegmentDB()
        pcb = self._mk_pcb(-1)
        cur_rec = create_mock_full({"pcb": self._mk_pcb(0)})
        inst._db = create_mock_full(return_value={0: {'record': cur_rec}})
        record = create_mock_full({'id': "idstr"})
        db_rec.return_value = record
        # Call
        ntools.eq_(inst.update(pcb), DBResult.NONE)
        # Tests
        pcb.get_expiration_time.assert_called_once_with()
        cur_rec.pcb.get_expiration_time.assert_called_once_with()

    @patch("lib.path_db.PathSegmentDBRecord", autospec=True)
    def test_update(self, db_rec):
        inst = PathSegmentDB()
        pcb = self._mk_pcb(1)
        cur_rec = create_mock_full({"pcb": self._mk_pcb(0), "id": "cur rec",
                                    "exp_time": 44})
        inst._db = create_mock_full(return_value={0: {'record': cur_rec}})
        db_rec.return_value = create_mock_full({'id': "record", 'exp_time': 32})
        # Call
        ntools.eq_(inst.update(pcb), DBResult.ENTRY_UPDATED)
        # Tests
        ntools.eq_(cur_rec.pcb, pcb)

    @patch("lib.path_store.SCIONTime.get_time", new_callable=create_mock)
    @patch("lib.path_db.PathSegmentDBRecord", autospec=True)
    def test_with_segment_ttl(self, db_rec, time):
        segment_ttl = 300
        inst = PathSegmentDB(segment_ttl)
        cur_rec = create_mock(['pcb', 'id', 'exp_time'])
        cur_rec.pcb = self._mk_pcb(0)
        cur_rec.exp_time = 10
        inst._db = create_mock_full(return_value={0: {'record': cur_rec}})
        pcb = self._mk_pcb(1)
        db_rec.return_value = create_mock(['id'])
        time.return_value = 1
        # Call
        inst.update(pcb)
        # Tests
        db_rec.assert_called_once_with(pcb, segment_ttl + time.return_value)
        ntools.eq_(cur_rec.exp_time, 301)


class TestPathSegmentDBDelete(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.delete
    """
    def test_basic(self):
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock(['delete'])
        pth_seg_db._db.return_value = ["data1"]
        ntools.eq_(pth_seg_db.delete("data1"), DBResult.ENTRY_DELETED)
        pth_seg_db._db.assert_called_once_with(id="data1")
        pth_seg_db._db.delete.assert_called_once_with(["data1"])

    def test_not_present(self):
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock()
        pth_seg_db._db.return_value = False
        ntools.eq_(pth_seg_db.delete("data"), DBResult.NONE)


class TestPathSegmentDBDeleteAll(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.delete_all
    """
    def test(self):
        inst = PathSegmentDB()
        inst.delete = create_mock()
        inst.delete.side_effect = (
            DBResult.ENTRY_DELETED, DBResult.NONE, DBResult.ENTRY_DELETED
        )
        # Call
        ntools.eq_(inst.delete_all((0, 1, 2)), 2)
        # Tests
        assert_these_calls(inst.delete, [call(i) for i in (0, 1, 2)])


class TestPathSegmentDBCall(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.__call__
    """
    def test(self):
        inst = PathSegmentDB()
        inst._parse_call_kwargs = create_mock()
        inst._parse_call_kwargs.return_value = {"arg1": "val1"}
        inst._exp_call_records = create_mock()
        inst._sort_call_pcbs = create_mock()
        inst._db = create_mock()
        # Call
        ntools.eq_(inst("data", a="b"), inst._sort_call_pcbs.return_value)
        # Tests
        inst._parse_call_kwargs.assert_called_once_with({"a": "b"})
        inst._db.assert_called_once_with("data", arg1="val1")
        inst._exp_call_records.assert_called_once_with(inst._db.return_value)
        inst._sort_call_pcbs.assert_called_once_with(
            False, inst._exp_call_records.return_value)


class TestPathSegmentDBExpCallRecords(object):
    """
    Unit tests for lib.path_db.PathSegmentDB._exp_call_records
    """
    @patch("lib.path_store.SCIONTime.get_time", new_callable=create_mock)
    def test(self, time):
        inst = PathSegmentDB()
        inst._db = create_mock(['delete'])
        recs = []
        for i in range(5):
            rec = create_mock(['exp_time', 'pcb'])
            rec.exp_time = i
            rec.pcb = create_mock(["short_desc"])
            recs.append({'record': rec})
        time.return_value = 2
        # Call
        ntools.eq_(inst._exp_call_records(recs), recs[2:])
        # Tests
        inst._db.delete.assert_called_once_with(recs[:2])


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
