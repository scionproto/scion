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
from Crypto.Hash import SHA256
from pydblite.pydblite import Base


class PathSegmentDBRecord(object):
    """
    Path record that gets stored in the the PathSegmentDB.
    """
    def __init__(self, pcb):
        assert isinstance(pcb, PathSegment)
        self.pcb = pcb
        self._id = None
        # Fidelity can be used to configure the desirability of a path. For
        # now we just use path length.
        self.fidelity = pcb.iof.hops

    @property
    def id(self):
        """
        Returns the unique ID of a path.
        """
        if self._id is None:
            id_str = ""
            for ad in self.pcb.ads:
                id_str += "".join([str(ad.pcbm.ad_id),
                                   str(ad.pcbm.hof.ingress_if),
                                   str(ad.pcbm.hof.egress_if)])
                id_str += ","
            id_str += str(self.pcb.iof.timestamp)
            id_str = id_str.encode('utf-8')
            self._id = SHA256.new(id_str).hexdigest()

        return self._id

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
        db.create('record', 'src_isd', 'src_ad', 'dst_isd', 'dst_ad')
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

    def _purge_paths(self, pcb, src_isd, src_ad, dst_isd, dst_ad):
        """
        Removes all paths that have identical hops but lower timestamps.

        Returns the PathSegment with the highest timestamp.
        """
        max_ts_pcb = pcb
        max_ts = pcb.iof.timestamp
        recs = self._db(src_isd=src_isd, src_ad=src_ad,
                        dst_isd=dst_isd, dst_ad=dst_ad)
        for rec in recs:
            rec_pcb = rec['record'].pcb
            if pcb.compare_hops(rec_pcb):
                if rec_pcb.iof.timestamp >= max_ts:
                    max_ts = rec_pcb.iof.timestamp
                    max_ts_pcb = rec_pcb
                else:
                    self._db.delete(rec)

        return max_ts_pcb

    def insert(self, pcb, src_isd, src_ad, dst_isd, dst_ad):
        """
        Inserts path into database.

        Returns the record ID of the inserted path or None if nothing was
        inserted.
        """
        assert isinstance(pcb, PathSegment)
        record = PathSegmentDBRecord(pcb)
        recs = self._db(record=record,
                        src_isd=src_isd, src_ad=src_ad,
                        dst_isd=dst_isd, dst_ad=dst_ad)
        if recs:
            return None
        else:
            rec_id = self._db.insert(record, src_isd, src_ad,
                                     dst_isd, dst_ad)
            max_pcb = self._purge_paths(pcb, src_isd, src_ad, dst_isd, dst_ad)
            if max_pcb == pcb:
                return rec_id
            else:
                return None

    def insert_all(self, pcbs, src_isd, src_ad, dst_isd, dst_ad):
        """
        Inserts a list of paths.
        """
        for pcb in pcbs:
            self.insert(pcb, src_isd, src_ad, dst_isd, dst_ad)

    def __call__(self, *args, **kwargs):
        """
        Selection by field values.

        Returns a sorted (path fidelity) list of paths according to the
        criterias specified.
        """
        res = sorted([r['record'] for r in self._db(*args, **kwargs)],
                     key=lambda x: x.fidelity)
        return [r.pcb for r in res]

    def __len__(self):
        return len(self._db)
