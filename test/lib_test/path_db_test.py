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
from unittest.mock import patch, MagicMock, call

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


class TestPathSegmentDBRecordInit(object):
    """
    Unit tests for lib.path_db.PathSegmentDBRecord.__init__
    """
    def test_basic(self):
        pcb = MagicMock(spec_set=['segment_id', 'iof', '__class__'])
        pcb.segment_id = "data1"
        pcb.iof.hops = "data2"
        pcb.__class__ = PathSegment
        pth_seg_db_rec = PathSegmentDBRecord(pcb)
        ntools.eq_(pth_seg_db_rec.pcb, pcb)
        ntools.eq_(pth_seg_db_rec.id, "data1")
        ntools.eq_(pth_seg_db_rec.fidelity, "data2")


class TestPathSegmentDBRecordEq(object):
    """
    Unit tests for lib.path_db.PathSegmentDBRecord.__eq__
    """
    def test_eq(self):
        pcb = MagicMock(spec_set=['segment_id', 'iof', '__class__'])
        pcb.__class__ = PathSegment
        pth_seg_db_rec1 = PathSegmentDBRecord(pcb)
        pth_seg_db_rec2 = PathSegmentDBRecord(pcb)
        id_ = "data"
        pth_seg_db_rec1.id = id_
        pth_seg_db_rec2.id = id_
        ntools.eq_(pth_seg_db_rec1, pth_seg_db_rec2)

    def test_neq(self):
        pcb = MagicMock(spec_set=['segment_id', 'iof', '__class__'])
        pcb.__class__ = PathSegment
        pth_seg_db_rec1 = PathSegmentDBRecord(pcb)
        pth_seg_db_rec2 = PathSegmentDBRecord(pcb)
        pth_seg_db_rec1.id = "data1"
        pth_seg_db_rec2.id = "data2"
        ntools.assert_not_equals(pth_seg_db_rec1, pth_seg_db_rec2)

    def test_type_neq(self):
        pcb = MagicMock(spec_set=['segment_id', 'iof', '__class__'])
        pcb.__class__ = PathSegment
        pth_seg_db_rec1 = PathSegmentDBRecord(pcb)
        pth_seg_db_rec2 = b"test"
        ntools.assert_not_equals(pth_seg_db_rec1, pth_seg_db_rec2)


class TestPathSegmentDBRecordHash(object):
    """
    Unit tests for lib.path_db.PathSegmentDBRecord.__hash__
    """
    def test_basic(self):
        pcb = MagicMock(spec_set=['segment_id', 'iof', '__class__'])
        pcb.__class__ = PathSegment
        pth_seg_db_rec = PathSegmentDBRecord(pcb)
        pth_seg_db_rec.id = 4
        ntools.eq_(hash(pth_seg_db_rec), 4)


class TestPathSegmentDBInit(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.__init__
    """
    @patch("lib.path_db.Base", autospec=True)
    def test_basic(self, base):
        db = MagicMock(spec_set=['create', 'create_index'])
        base.return_value = db
        pth_seg_db = PathSegmentDB()
        base.assert_called_once_with("", save_to_file=False)
        db.create.assert_called_once_with('record', 'id', 'src_isd', 'src_ad',
                                          'dst_isd', 'dst_ad', mode='override')
        db.create_index.assert_has_calls([call('id'), call('dst_isd'),
                                          call('dst_ad')])
        ntools.eq_(pth_seg_db._db, db)


class TestPathSegmentDBGetItem(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.__getitem__
    """
    def test_basic(self):
        cur_rec = MagicMock(spec_set=['pcb'])
        cur_rec.pcb = "data1"
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = MagicMock(spec_set=[])
        pth_seg_db._db.return_value = {0: {'record': cur_rec}}
        ntools.eq_(pth_seg_db["data2"], "data1")
        pth_seg_db._db.assert_called_once_with(id="data2")

    def test_not_present(self):
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = MagicMock(spec_set=[])
        pth_seg_db._db.return_value = False
        ntools.assert_is_none(pth_seg_db["data"])


class TestPathSegmentDBContains(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.__contains__
    """
    def test_basic(self):
        recs = MagicMock(spec_set=['__len__'])
        recs.__len__.return_value = 1
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = MagicMock(spec_set=[])
        pth_seg_db._db.return_value = recs
        ntools.assert_true("data" in pth_seg_db)
        pth_seg_db._db.assert_called_once_with(id="data")

    def test_not_present(self):
        recs = MagicMock(spec_set=['__len__'])
        recs.__len__.return_value = 0
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = MagicMock(spec_set=[])
        pth_seg_db._db.return_value = recs
        ntools.assert_false("data" in pth_seg_db)


class TestPathSegmentDBUpdate(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.update
    """
    @patch("lib.path_db.PathSegmentDBRecord", autospec=True)
    def test_basic(self, db_rec):
        pcb = MagicMock(spec_set=['__class__'])
        pcb.__class__ = PathSegment
        record = MagicMock(spec_set=['id'])
        record.id = "str"
        db_rec.return_value = record
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = MagicMock(spec_set=['insert'])
        pth_seg_db._db.return_value = []
        ntools.eq_(pth_seg_db.update(pcb, 1, 2, 3, 4), DBResult.ENTRY_ADDED)
        db_rec.assert_called_once_with(pcb)
        pth_seg_db._db.assert_called_once_with(id="str")
        pth_seg_db._db.insert.assert_called_once_with(record, "str", 1, 2, 3, 4)

    @patch("lib.path_db.PathSegmentDBRecord", autospec=True)
    def test_none(self, db_rec):
        pcb = MagicMock(spec_set=['__class__', 'get_expiration_time'])
        pcb.__class__ = PathSegment
        pcb.get_expiration_time.return_value = -1
        record = MagicMock(spec_set=['id'])
        record.id = "str"
        cur_rec = MagicMock(spec_set=['pcb'])
        cur_rec.pcb.get_expiration_time.return_value = 0
        db_rec.return_value = record
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = MagicMock(spec_set=[])
        pth_seg_db._db.return_value = {0: {'record': cur_rec}}
        ntools.eq_(pth_seg_db.update(pcb, 1, 2, 3, 4), DBResult.NONE)
        pcb.get_expiration_time.assert_called_once_with()
        cur_rec.pcb.get_expiration_time.assert_called_once_with()

    @patch("lib.path_db.PathSegmentDBRecord", autospec=True)
    def test_entry_update(self, db_rec):
        pcb = MagicMock(spec_set=['__class__', 'get_expiration_time'])
        pcb.__class__ = PathSegment
        pcb.get_expiration_time.return_value = 1
        record = MagicMock(spec_set=['id'])
        record.id = "str"
        cur_rec = MagicMock(spec_set=['pcb', 'id'])
        cur_rec.pcb.get_expiration_time.return_value = 0
        db_rec.return_value = record
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = MagicMock(spec_set=[])
        pth_seg_db._db.return_value = {0: {'record': cur_rec}}
        ntools.eq_(pth_seg_db.update(pcb, 1, 2, 3, 4), DBResult.ENTRY_UPDATED)
        ntools.eq_(cur_rec.pcb, pcb)


class TestPathSegmentDBUpdateAll(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.update_all
    """
    def test_basic(self):
        pcbs = []
        for i in range(5):
            pcbs.append("data" + str(i))
        pth_seg_db = PathSegmentDB()
        pth_seg_db.update = MagicMock(spec_set=[])
        pth_seg_db.update_all(pcbs, 1, 2, 3, 4)
        pth_seg_db.update.assert_has_calls([call(i, 1, 2, 3, 4) for i in pcbs])


class TestPathSegmentDBDelete(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.delete
    """
    def test_basic(self):
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = MagicMock(spec_set=['delete'])
        pth_seg_db._db.return_value = "data1"
        ntools.eq_(pth_seg_db.delete("data2"), DBResult.ENTRY_DELETED)
        pth_seg_db._db.assert_called_once_with(id="data2")
        pth_seg_db._db.delete.assert_called_once_with("data1")

    def test_not_present(self):
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = MagicMock(spec_set=[])
        pth_seg_db._db.return_value = False
        ntools.eq_(pth_seg_db.delete("data"), DBResult.NONE)


class TestPathSegmentDBCall(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.__call__
    """
    @patch("lib.path_store.SCIONTime.get_time", spec_set=[],
           new_callable=MagicMock)
    def test_basic(self, time):
        recs = []
        for i in range(5):
            cur_rec = MagicMock(spec_set=['pcb', 'fidelity'])
            cur_rec.pcb.get_expiration_time.return_value = 1
            cur_rec.fidelity = i
            recs.append({'record': cur_rec})
        time.return_value = 0
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = MagicMock(spec_set=['delete'])
        pth_seg_db._db.return_value = recs
        ntools.eq_(pth_seg_db("data"), [r['record'].pcb for r in recs])
        pth_seg_db._db.assert_called_once_with("data")
        time.assert_called_once_with()
        pth_seg_db._db.delete.assert_called_once_with([])
        for i in range(5):
            recs[i]['record'].pcb.get_expiration_time.assert_called_once_with()

    @patch("lib.path_store.SCIONTime.get_time", spec_set=[],
           new_callable=MagicMock)
    def test_expiration(self, time):
        recs = []
        for i in range(5):
            cur_rec = MagicMock(spec_set=['pcb'])
            cur_rec.pcb.get_expiration_time.return_value = -1
            recs.append({'record': cur_rec, 'src_isd': 0,
                         'src_ad': 1, 'dst_isd': 2, 'dst_ad': 3})
        time.return_value = 0
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = MagicMock(spec_set=['delete'])
        pth_seg_db._db.return_value = recs
        ntools.eq_(pth_seg_db("data"), [])
        pth_seg_db._db.delete.assert_called_once_with(recs)


class TestPathSegmentDBLen(object):
    """
    Unit tests for lib.path_db.PathSegmentDB.__len__
    """
    def test_basic(self):
        pth_seg_db = PathSegmentDB()
        pth_seg_db._db = MagicMock(spec_set=['__len__'])
        pth_seg_db._db.__len__.return_value = 5
        ntools.eq_(len(pth_seg_db), 5)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
