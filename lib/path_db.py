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
import threading

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

    def __init__(self, pcb, exp_time=None):
        """
        Initialize an instance of the class PathSegmentDBRecord.

        :param pcb: The PCB stored in the record.
        :type pcb: :class:`lib.packet.pcb.PathSegment`
        :param int exp_time: The expiration time for the record (in seconds),
            or None to just use the segment's expiration time.
        """
        assert isinstance(pcb, PathSegment)
        self.pcb = pcb
        self.id = pcb.get_hops_hash()
        # Fidelity can be used to configure the desirability of a path. For
        # now we just use path length.
        self.fidelity = pcb.iof.hops
        if exp_time:
            self.exp_time = min(pcb.get_expiration_time(), exp_time)
        else:
            self.exp_time = pcb.get_expiration_time()

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
    """

    def __init__(self, segment_ttl=None, max_res_no=None):
        """
        Initialize an instance of the class PathSegmentDB.

        :param int segment_ttl: The TTL for each record in the database (in s)
            or None to just use the segment's expiration time.
        :param int max_res_no: Number of results returned for a query.
        """
        self._db = Base("", save_to_file=False)
        self._db.create('record', 'id', 'first_isd', 'first_ad', 'last_isd',
                        'last_ad', mode='override')
        self._db.create_index('id')
        self._db.create_index('last_isd')
        self._db.create_index('last_ad')
        self._lock = threading.Lock()
        self._segment_ttl = segment_ttl
        self._max_res_no = max_res_no

    def __getitem__(self, seg_id):
        """
        Return a path object by segment id.

        :param seg_id:
        :type seg_id:

        :returns:
        :rtype:
        """
        with self._lock:
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
        with self._lock:
            recs = self._db(id=seg_id)
        return len(recs) > 0

    def update(self, pcb, first_isd, first_ad, last_isd, last_ad):
        """
        Insert path into database.
        Return the result of the operation.

        :param pcb:
        :type pcb:
        :param first_isd:
        :type first_isd:
        :param first_ad:
        :type first_ad:
        :param last_isd:
        :type last_isd:
        :param last_ad:
        :type last_ad:

        :returns:
        :rtype:
        """
        assert isinstance(pcb, PathSegment)
        if self._segment_ttl:
            now = int(SCIONTime.get_time())
            record = PathSegmentDBRecord(pcb, now + self._segment_ttl)
        else:
            record = PathSegmentDBRecord(pcb)
        with self._lock:
            recs = self._db(id=record.id)
            assert len(recs) <= 1, "PathDB contains > 1 path with the same ID"
            if not recs:
                self._db.insert(record, record.id, first_isd,
                                first_ad, last_isd, last_ad)
                return DBResult.ENTRY_ADDED
            cur_rec = recs[0]['record']
            if pcb.get_expiration_time() < cur_rec.pcb.get_expiration_time():
                return DBResult.NONE
            cur_rec.pcb = pcb
            if self._segment_ttl:
                cur_rec.exp_time = now + self._segment_ttl
            else:
                cur_rec.exp_time = pcb.get_expiration_time()
            return DBResult.ENTRY_UPDATED

    def update_all(self, pcbs, first_isd, first_ad, last_isd, last_ad):
        """
        Updates a list of paths.

        :param pcbs:
        :type pcbs:
        :param first_isd:
        :type first_isd:
        :param first_ad:
        :type first_ad:
        :param last_isd:
        :type last_isd:
        :param last_ad:
        :type last_ad:
        """
        for pcb in pcbs:
            self.update(pcb, first_isd, first_ad, last_isd, last_ad)

    def delete(self, segment_id):
        """
        Deletes a path segment with a given ID.

        :param segment_id:
        :type segment_id:

        :returns:
        :rtype:
        """
        with self._lock:
            recs = self._db(id=segment_id)
            if not recs:
                return DBResult.NONE
            self._db.delete(recs)
        return DBResult.ENTRY_DELETED

    def delete_all(self, segment_ids):
        """
        Deletes paths with the given IDs and returns the number of deletions.

        :param segment_ids: The segment IDs to remove.
        :type segment_ids: list

        :returns: The number of deletions.
        :rtype: int
        """
        deletions = 0
        for seg_id in segment_ids:
            if self.delete(seg_id) == DBResult.ENTRY_DELETED:
                deletions += 1
        return deletions

    def __call__(self, full=False, *args, **kwargs):
        """
        Selection by field values.

        Returns a sorted (path fidelity) list of paths according to the
        criterias specified.

        :param full: Return list of results not bounded by self._max_res_no.
        :type full: bool
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:

        :returns:
        :rtype:
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
                    logging.debug("Path-Segment (%(first_isd)d, %(first_ad)d) "
                                  "-> (%(last_isd)d, %(last_ad)d) expired.", r)
                else:
                    valid_recs.append(r)
            self._db.delete(expired_recs)
        pcbs = sorted([r['record'] for r in valid_recs],
                      key=lambda x: x.fidelity)
        if self._max_res_no and not full:
            pcbs = pcbs[:self._max_res_no]
        return [p.pcb for p in pcbs]

    def __len__(self):
        """


        :returns:
        :rtype: int
        """
        with self._lock:
            return len(self._db)
