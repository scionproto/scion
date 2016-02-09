# Copyright 2016 ETH Zurich
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
:mod:`seg_db` --- SIBRA steady path segment database
====================================================
"""
# Stdlib
import logging
import threading

# External packages
from pydblite.pydblite import Base

# SCION
from lib.sibra.segment import SibraSegment
from lib.path_db import DBResult
from lib.util import SCIONTime


class SibraDBRecord(object):
    """
    Sibra steady path segment that gets stored in the SibraSegmentDB.
    """
    def __init__(self, seg):
        assert isinstance(seg, SibraSegment)
        self.seg = seg
        self.id = self.seg.id
        self._update_attrs()

    def update(self, seg):
        assert isinstance(seg, SibraSegment)
        assert self.id == seg.id
        if seg.expiry() < self.exp_time:
            return DBResult.NONE
        self.seg = seg
        self._update_attrs()
        return DBResult.ENTRY_UPDATED

    def _update_attrs(self):
        # Fidelity can be used to configure the desirability of a path. For now
        # we just use path length.
        self.fidelity = self.seg.num_hops()
        self.exp_time = self.seg.expiry()

    def __eq__(self, other):
        return self.id == other.id

    def __hash__(self):
        return self.id


class SibraSegmentDB(object):
    """
    Simple database for segments using PyDBLite.
    """
    def __init__(self, segment_ttl=None, max_res_no=None):
        self._db = Base("", save_to_file=False)
        self._db.create('record', 'id', 'first_isd', 'first_ad', 'last_isd',
                        'last_ad', mode='override')
        self._db.create_index('id')
        self._db.create_index('last_isd')
        self._db.create_index('last_ad')
        self._lock = threading.Lock()

    def __getitem__(self, seg_id):
        with self._lock:
            recs = self._db(id=seg_id)
        assert len(recs) <= 1
        if recs:
            return recs[0]['record'].seg
        return None

    def __contains__(self, seg_id):
        return bool(self[seg_id])

    def update(self, seg):
        assert isinstance(seg, SibraSegment)
        with self._lock:
            recs = self._db(id=seg.id)
            assert len(recs) <= 1
            if not recs:
                rec = SibraDBRecord(seg)
                self._db.insert(rec, seg.id, seg.src.isd, seg.src.ad,
                                seg.dst.isd, seg.dst.ad)
                return DBResult.ENTRY_ADDED
            cur_rec = recs[0]['record']
            return cur_rec.update(seg)

    def delete(self, seg_id):
        with self._lock:
            recs = self._db(id=seg_id)
            if not recs:
                return DBResult.NONE
            self._db.delete(recs)
        return DBResult.ENTRY_DELETED

    def __call__(self, *args, **kwargs):
        """
        Selection by field values.

        Returns a sorted (path fidelity) list of paths according to the
        criterias specified.
        """
        now = int(SCIONTime.get_time())
        expired_recs = []
        valid_recs = []
        with self._lock:
            recs = self._db(*args, **kwargs)
            # Remove expired path from the cache.
            for r in recs:
                if r['record'].exp_time < now:
                    expired_recs.append(r)
                    logging.debug("Expired: %s", r['record'].seg)
                else:
                    valid_recs.append(r)
            self._db.delete(expired_recs)
        records = sorted([r['record'] for r in valid_recs],
                         key=lambda x: x.fidelity)
        return [r.seg for r in records]

    def __len__(self):
        with self._lock:
            return len(self._db)
