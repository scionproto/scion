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
:mod:`path_db` --- Path Database
========================================
"""
# Stdlib
import logging
import time

# External packages
from pydblite.pydblite import Base

# SCION
from lib.packet.pcb import PathSegment


class DBResult(object):
    """
    Enum type for the different result of an insertion.
    """
    NONE = 0
    ENTRY_ADDED = 1
    ENTRY_UPDATED = 2
    ENTRY_DELETED = 3


class PathSegmentDBRecord(object):
    """
    Path record that gets stored in the the PathSegmentDB.
    """
    def __init__(self, pcb):
        assert isinstance(pcb, PathSegment)
        self.pcb = pcb
        self.id = pcb.segment_id
        # Fidelity can be used to configure the desirability of a path. For
        # now we just use path length.
        self.fidelity = pcb.iof.hops

    def __eq__(self, other):
        if type(other) is type(self):
            return self.id == other.id
        else:
            return False

    def __hash__(self):
        return self.id


class PathSegmentDB(object):
    """
    Simple database for paths using PyDBLite.
    """
    def __init__(self):
        db = Base("", save_to_file=False)
        db.create('record', 'id', 'src_isd', 'src_ad', 'dst_isd',
                  'dst_ad', mode='override')
        db.create_index('id')
        db.create_index('dst_isd')
        db.create_index('dst_ad')

        self._db = db

    def __getitem__(self, seg_id):
        """
        Returns a path object by segment id.
        """
        recs = self._db(id=seg_id)
        if recs:
            return recs[0]['record'].pcb
        else:
            return None

    def __contains__(self, seg_id):
        recs = self._db(id=seg_id)

        return len(recs) > 0

    def update(self, pcb, src_isd, src_ad, dst_isd, dst_ad):
        """
        Inserts path into database.

        Returns the result of the operation.
        """
        assert isinstance(pcb, PathSegment)
        record = PathSegmentDBRecord(pcb)
        recs = self._db(id=record.id)

        assert len(recs) <= 1, "PathDB contains > 1 path with the same ID"

        if not recs:
            self._db.insert(record, record.id, src_isd, src_ad, dst_isd, dst_ad)
            logging.debug("Created new entry in DB for (%d, %d) -> (%d, %d):" +
                          "\n%s", src_isd, src_ad, dst_isd, dst_ad, record.id)
            return DBResult.ENTRY_ADDED
        else:
            cur_rec = recs[0]['record']
            if pcb.get_expiration_time() <= cur_rec.pcb.get_expiration_time():
                logging.debug("Fresher path-segment for (%d, %d) -> (%d, %d) " +
                              "already known", src_isd, src_ad, dst_isd, dst_ad)
                return DBResult.NONE
            else:
                cur_rec.pcb = pcb
                logging.debug("Updated segment with ID %s", cur_rec.id)
                return DBResult.ENTRY_UPDATED

    def update_all(self, pcbs, src_isd, src_ad, dst_isd, dst_ad):
        """
        Updates a list of paths.
        """
        for pcb in pcbs:
            self.update(pcb, src_isd, src_ad, dst_isd, dst_ad)

    def delete(self, segment_id):
        """
        Deletes a path segment with a given ID.
        """
        recs = self._db(id=segment_id)
        if recs:
            self._db.delete(recs)
            return DBResult.ENTRY_DELETED
        else:
            return DBResult.NONE

    def __call__(self, *args, **kwargs):
        """
        Selection by field values.

        Returns a sorted (path fidelity) list of paths according to the
        criterias specified.
        """
        recs = self._db(*args, **kwargs)
        now = int(time.time())
        expired_recs = []
        valid_recs = []
        # Remove expired path from the cache.
        for r in recs:
            if r['record'].pcb.get_expiration_time() < now:
                expired_recs.append(r)
                logging.debug("Path-Segment (%d, %d) -> (%d, %d) expired.",
                              r['src_isd'], r['src_ad'],
                              r['dst_isd'], r['dst_ad'])
            else:
                valid_recs.append(r)
        self._db.delete(expired_recs)

        pcbs = sorted([r['record'] for r in valid_recs],
                      key=lambda x: x.fidelity)
        return [p.pcb for p in pcbs]

    def __len__(self):
        return len(self._db)
