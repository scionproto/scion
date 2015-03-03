"""
path_db.py

Copyright 2015 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from lib.packet.pcb import PathSegment
import logging
import time

from pydblite.pydblite import Base


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
        db.create('record', 'id', 'src_isd', 'src_ad', 'dst_isd', 'dst_ad')
        db.create_index('id')
        db.create_index('dst_isd')
        db.create_index('dst_ad')

        self._db = db

    def __getitem__(self, rec_id):
        """
        Returns a path object by record id.
        """
        if rec_id in self._db:
            return self._db[rec_id]['record'].pcb
        else:
            return None

    def update(self, pcb, src_isd, src_ad, dst_isd, dst_ad):
        """
        Inserts path into database.

        Returns the record ID of the updated path or None if nothing was
        updated.
        """
        assert isinstance(pcb, PathSegment)
        record = PathSegmentDBRecord(pcb)
        recs = self._db(id=record.id)

        assert len(recs) <= 1, "PathDB contains > 1 path with the same ID"

        if not recs:
            rec_id = self._db.insert(record, record.id, src_isd, src_ad,
                                     dst_isd, dst_ad)
            logging.debug("Created new entry in DB for (%d, %d) -> (%d, %d):" +
                          "\n%s", src_isd, src_ad, dst_isd, dst_ad, record.id)
            return rec_id
        else:
            cur_rec = recs[0]['record']
            rec_id = recs[0]['__id__']
            if pcb.get_expiration_time() <= cur_rec.pcb.get_expiration_time():
                logging.debug("Fresher path-segment for (%d, %d) -> (%d, %d) " +
                              "already known", src_isd, src_ad, dst_isd, dst_ad)
                return None
            else:
                cur_rec.pcb.set_timestamp(pcb.get_timestamp())
                logging.debug("Updated expiration time for segment with ID %s",
                              cur_rec.id)
                return rec_id

    def update_all(self, pcbs, src_isd, src_ad, dst_isd, dst_ad):
        """
        Updates a list of paths.
        """
        for pcb in pcbs:
            self.update(pcb, src_isd, src_ad, dst_isd, dst_ad)

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
