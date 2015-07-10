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
================================
"""
# Stdlib
import logging

# External packages
from pydblite.pydblite import Base

# SCION
from lib.packet.pcb import PathSegment
from lib.util import SCIONTime


class DBResult(object):
    """
    Enum type for the different result of an insertion.

    :cvar NONE:
    :type NONE: int
    :cvar ENTRY_ADDED:
    :type ENTRY_ADDED: int
    :cvar ENTRY_UPDATED:
    :type ENTRY_UPDATED: int
    :cvar ENTRY_DELETED:
    :type ENTRY_DELETED: int
    """
    NONE = 0
    ENTRY_ADDED = 1
    ENTRY_UPDATED = 2
    ENTRY_DELETED = 3


class PathSegmentDBRecord(object):
    """
    Path record that gets stored in the the PathSegmentDB.

    :ivar pcb:
    :type pcb:
    :ivar id:
    :type id:
    :ivar fidelity:
    :type fidelity:
    """

    def __init__(self, pcb):
        """
        Initialize an instance of the class PathSegmentDBRecord.

        :param pcb:
        :type pcb:
        """
        assert isinstance(pcb, PathSegment)
        self.pcb = pcb
        self.id = pcb.segment_id
        # Fidelity can be used to configure the desirability of a path. For
        # now we just use path length.
        self.fidelity = pcb.iof.hops

    def __eq__(self, other):
        """

        :param other:
        :type other:

        :returns:
        :rtype:
        """
        if type(other) is type(self):
            return self.id == other.id
        else:
            return False

    def __hash__(self):
        """

        :returns:
        :rtype:
        """
        return self.id


class PathSegmentDB(object):
    """
    Simple database for paths using PyDBLite.

    :ivar _db:
    :type _db:
    """

    def __init__(self):
        """
        Initialize an instance of the class PathSegmentDB.
        """
        db = Base("", save_to_file=False)
        db.create('record', 'id', 'src_isd', 'src_ad', 'dst_isd',
                  'dst_ad', mode='override')
        db.create_index('id')
        db.create_index('dst_isd')
        db.create_index('dst_ad')
        self._db = db

    def __getitem__(self, seg_id):
        """
        Return a path object by segment id.

        :param seg_id:
        :type seg_id:

        :returns:
        :rtype:
        """
        recs = self._db(id=seg_id)
        if recs:
            return recs[0]['record'].pcb
        else:
            return None

    def __contains__(self, seg_id):
        """

        :param seg_id:
        :type seg_id:

        :returns:
        :rtype:
        """
        recs = self._db(id=seg_id)
        return len(recs) > 0

    def update(self, pcb, src_isd, src_ad, dst_isd, dst_ad):
        """
        Insert path into database.
        Return the result of the operation.

        :param pcb:
        :type pcb:
        :param src_isd:
        :type src_isd:
        :param src_ad:
        :type src_ad:
        :param dst_isd:
        :type dst_isd:
        :param dst_ad:
        :type dst_ad:

        :returns:
        :rtype:
        """
        assert isinstance(pcb, PathSegment)
        record = PathSegmentDBRecord(pcb)
        recs = self._db(id=record.id)
        assert len(recs) <= 1, "PathDB contains > 1 path with the same ID"
        if not recs:
            self._db.insert(record, record.id, src_isd, src_ad, dst_isd, dst_ad)
            return DBResult.ENTRY_ADDED
        else:
            cur_rec = recs[0]['record']
            if pcb.get_expiration_time() <= cur_rec.pcb.get_expiration_time():
                return DBResult.NONE
            else:
                cur_rec.pcb = pcb
                return DBResult.ENTRY_UPDATED

    def update_all(self, pcbs, src_isd, src_ad, dst_isd, dst_ad):
        """
        Updates a list of paths.

        :param pcbs:
        :type pcbs:
        :param src_isd:
        :type src_isd:
        :param src_ad:
        :type src_ad:
        :param dst_isd:
        :type dst_isd:
        :param dst_ad:
        :type dst_ad:
        """
        for pcb in pcbs:
            self.update(pcb, src_isd, src_ad, dst_isd, dst_ad)

    def delete(self, segment_id):
        """
        Deletes a path segment with a given ID.

        :param segment_id:
        :type segment_id:

        :returns:
        :rtype:
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

        :param args:
        :type args:
        :param kwargs:
        :type kwargs:

        :returns:
        :rtype:
        """
        recs = self._db(*args, **kwargs)
        now = int(SCIONTime.get_time())
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
        """


        :returns:
        :rtype: int
        """
        return len(self._db)
