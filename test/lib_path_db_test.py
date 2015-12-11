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
from test.testcommon import assert_these_calls, create_mock


class TestPathSegmentDBRecordInit(object):
    """
    Unit tests for lib.path_db.PathSegmentDBRecord.__init__
    """
    def test_basic(self):
        pcb = create_mock(['get_hops_hash', 'iof', 'get_expiration_time'],
                          class_=PathSegment)
        pcb.get_hops_hash.return_value = "data1"
        pcb.get_expiration_time.return_value = 1
        pcb.iof = create_mock(["hops"])
        pcb.iof.hops = "data2"
        pth_seg_db_rec = PathSegmentDBRecord(pcb)
        ntools.eq_(pth_seg_db_rec.pcb, pcb)
        ntools.eq_(pth_seg_db_rec.id, "data1")
        ntools.eq_(pth_seg_db_rec.fidelity, "data2")
        ntools.eq_(pth_seg_db_rec.exp_time, 1)

    def test_non_default(self):
        pcb = create_mock(['get_hops_hash', 'iof', 'get_expiration_time'],
                          class_=PathSegment)
        pcb.get_hops_hash.return_value = "data1"
        pcb.get_expiration_time.return_value = 500
        pcb.iof = create_mock(["hops"])
        pcb.iof.hops = "data2"
        exp_time = 300
        pth_seg_db_rec = PathSegmentDBRecord(pcb, exp_time)
        ntools.eq_(pth_seg_db_rec.exp_time, exp_time)


class TestPathSegmentDBRecordEq(object):
    """
    Unit tests for lib.path_db.PathSegmentDBRecord.__eq__
    """
    def test_eq(self):
        pcb = create_mock(['get_hops_hash', 'iof', 'get_expiration_time'],
                          class_=PathSegment)
        pcb.iof = create_mock(["hops"])
        pth_seg_db_rec1 = PathSegmentDBRecord(pcb)
        pth_seg_db_rec2 = PathSegmentDBRecord(pcb)
        id_ = "data"
        pth_seg_db_rec1.id = id_
        pth_seg_db_rec2.id = id_
        ntools.eq_(pth_seg_db_rec1, pth_seg_db_rec2)

    def test_neq(self):
        pcb = create_mock(['get_hops_hash', 'iof', 'get_expiration_time'],
                          class_=PathSegment)
        pcb.iof = create_mock(["hops"])
        pth_seg_db_rec1 = PathSegmentDBRecord(pcb)
        pth_seg_db_rec2 = PathSegmentDBRecord(pcb)
        pth_seg_db_rec1.id = "data1"
        pth_seg_db_rec2.id = "data2"
        ntools.assert_not_equals(pth_seg_db_rec1, pth_seg_db_rec2)

    def test_type_neq(self):
        pcb = create_mock(['get_hops_hash', 'iof', 'get_expiration_time'],
                          class_=PathSegment)
        pcb.iof = create_mock(["hops"])
        pth_seg_db_rec1 = PathSegmentDBRecord(pcb)
        pth_seg_db_rec2 = b"test"
        ntools.assert_not_equals(pth_seg_db_rec1, pth_seg_db_rec2)


class TestPathSegmentDBRecordHash(object):
    """
    Unit tests for lib.path_db.PathSegmentDBRecord.__hash__
    """
    def test_basic(self):
        pcb = create_mock(['get_hops_hash', 'iof', 'get_expiration_time'],
                          class_=PathSegment)
        pcb.iof = create_mock(["hops"])
        pth_seg_db_rec = PathSegmentDBRecord(pcb)
        pth_seg_db_rec.id = 4
        ntools.eq_(hash(pth_seg_db_rec), 4)


class TestPathSegmentDBInit(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.__init__
    """
    @patch("lib.path_db.Base", autospec=True)
    def test_basic(self, base):
        db = create_mock(['create', 'create_index'])
        base.return_value = db
        pth_seg_db = PathSegmentDB(300)
        base.assert_called_once_with("", save_to_file=False)
        db.create.assert_called_once_with('record', 'id', 'first_isd',
                                          'first_ad', 'last_isd', 'last_ad',
                                          mode='override')
        db.create_index.assert_has_calls([call('id'), call('last_isd'),
                                          call('last_ad')])
        ntools.eq_(pth_seg_db._db, db)
        ntools.eq_(pth_seg_db._segment_ttl, 300)


class TestPathSegmentDBGetItem(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.__getitem__
    """
    def test_basic(self):
        cur_rec = create_mock(['pcb'])
        cur_rec.pcb = "data1"
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock()
        pth_seg_db._db.return_value = {0: {'record': cur_rec}}
        ntools.eq_(pth_seg_db["data2"], "data1")
        pth_seg_db._db.assert_called_once_with(id="data2")

    def test_not_present(self):
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock()
        pth_seg_db._db.return_value = False
        ntools.assert_is_none(pth_seg_db["data"])


class TestPathSegmentDBContains(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.__contains__
    """
    def test_basic(self):
        recs = create_mock(['__len__'])
        recs.__len__.return_value = 1
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock()
        pth_seg_db._db.return_value = recs
        ntools.assert_true("data" in pth_seg_db)
        pth_seg_db._db.assert_called_once_with(id="data")

    def test_not_present(self):
        recs = create_mock(['__len__'])
        recs.__len__.return_value = 0
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock()
        pth_seg_db._db.return_value = recs
        ntools.assert_false("data" in pth_seg_db)


class TestPathSegmentDBUpdate(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.update
    """
    @patch("lib.path_db.PathSegmentDBRecord", autospec=True)
    def test_basic(self, db_rec):
        pcb = create_mock(class_=PathSegment)
        record = create_mock(['id'])
        record.id = "str"
        db_rec.return_value = record
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock(['insert'])
        pth_seg_db._db.return_value = []
        ntools.eq_(pth_seg_db.update(pcb, 1, 2, 3, 4), DBResult.ENTRY_ADDED)
        db_rec.assert_called_once_with(pcb)
        pth_seg_db._db.assert_called_once_with(id="str")
        pth_seg_db._db.insert.assert_called_once_with(record, "str", 1, 2, 3, 4)

    @patch("lib.path_db.PathSegmentDBRecord", autospec=True)
    def test_none(self, db_rec):
        pcb = create_mock(["get_expiration_time"], class_=PathSegment)
        pcb.get_expiration_time.return_value = -1
        record = create_mock(['id'])
        record.id = "str"
        cur_rec = create_mock(['pcb'])
        cur_rec.pcb = create_mock(["get_expiration_time"])
        cur_rec.pcb.get_expiration_time.return_value = 0
        db_rec.return_value = record
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock()
        pth_seg_db._db.return_value = {0: {'record': cur_rec}}
        ntools.eq_(pth_seg_db.update(pcb, 1, 2, 3, 4), DBResult.NONE)
        pcb.get_expiration_time.assert_called_once_with()
        cur_rec.pcb.get_expiration_time.assert_called_once_with()

    @patch("lib.path_db.PathSegmentDBRecord", autospec=True)
    def test_entry_update(self, db_rec):
        pcb = create_mock(["get_expiration_time"], class_=PathSegment)
        pcb.get_expiration_time.return_value = 1
        record = create_mock(['id', 'exp_time'])
        record.id = "str"
        cur_rec = create_mock(['pcb', 'id', 'exp_time'])
        cur_rec.pcb = create_mock(["get_expiration_time"])
        cur_rec.pcb.get_expiration_time.return_value = 0
        db_rec.return_value = record
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock()
        pth_seg_db._db.return_value = {0: {'record': cur_rec}}
        ntools.eq_(pth_seg_db.update(pcb, 1, 2, 3, 4), DBResult.ENTRY_UPDATED)
        ntools.eq_(cur_rec.pcb, pcb)

    @patch("lib.path_store.SCIONTime.get_time", new_callable=create_mock)
    @patch("lib.path_db.PathSegmentDBRecord", autospec=True)
    def test_with_segment_ttl(self, db_rec, time):
        pcb = create_mock(class_=PathSegment)
        record = create_mock(['id'])
        db_rec.return_value = record
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock(['insert'])
        pth_seg_db._db.return_value = []
        time.return_value = 1
        segment_ttl = 300
        pth_seg_db = PathSegmentDB(segment_ttl)
        # Call
        pth_seg_db.update(pcb, 1, 2, 3, 4)
        # Test
        db_rec.assert_called_once_with(pcb, segment_ttl + time.return_value)


class TestPathSegmentDBUpdateAll(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.update_all
    """
    def test_basic(self):
        pcbs = []
        for i in range(5):
            pcbs.append("data" + str(i))
        pth_seg_db = PathSegmentDB()
        pth_seg_db.update = create_mock()
        pth_seg_db.update_all(pcbs, 1, 2, 3, 4)
        pth_seg_db.update.assert_has_calls([call(i, 1, 2, 3, 4) for i in pcbs])


class TestPathSegmentDBDelete(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.delete
    """
    def test_basic(self):
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock(['delete'])
        pth_seg_db._db.return_value = "data1"
        ntools.eq_(pth_seg_db.delete("data2"), DBResult.ENTRY_DELETED)
        pth_seg_db._db.assert_called_once_with(id="data2")
        pth_seg_db._db.delete.assert_called_once_with("data1")

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
    @patch("lib.path_store.SCIONTime.get_time", new_callable=create_mock)
    def test_basic(self, time):
        recs = []
        for i in range(5):
            cur_rec = create_mock(['pcb', 'fidelity', 'exp_time'])
            cur_rec.exp_time = 1
            cur_rec.fidelity = i
            recs.append({'record': cur_rec})
        time.return_value = 0
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock(['delete'])
        pth_seg_db._db.return_value = recs
        ntools.eq_(pth_seg_db("data"), [r['record'].pcb for r in recs])
        pth_seg_db._db.assert_called_once_with()
        time.assert_called_once_with()
        pth_seg_db._db.delete.assert_called_once_with([])

    @patch("lib.path_store.SCIONTime.get_time", new_callable=create_mock)
    def test_expiration(self, time):
        recs = []
        for i in range(5):
            cur_rec = create_mock(['pcb', 'exp_time'])
            cur_rec.exp_time = -1
            recs.append({'record': cur_rec, 'first_isd': 0,
                         'first_ad': 1, 'last_isd': 2, 'last_ad': 3})
        time.return_value = 0
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock(['delete'])
        pth_seg_db._db.return_value = recs
        ntools.eq_(pth_seg_db("data"), [])
        pth_seg_db._db.delete.assert_called_once_with(recs)


class TestPathSegmentDBLen(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.__len__
    """
    def test_basic(self):
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = create_mock(['__len__'])
        pth_seg_db._db.__len__.return_value = 5
        ntools.eq_(len(pth_seg_db), 5)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
