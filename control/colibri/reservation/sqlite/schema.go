// Copyright 2020 ETH Zurich, Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sqlite

const (
	// SchemaVersion is the version of the SQLite schema understood by this backend.
	// Whenever changes to the schema are made, this version number should be increased
	// to prevent data corruption between incompatible database schemas.
	SchemaVersion = 1
	// Schema is the SQLite database layout.
	Schema = `CREATE TABLE seg_reservation (
		ROWID	INTEGER,
		id_as	INTEGER NOT NULL,
		id_suffix	INTEGER NOT NULL,
		ingress	INTEGER NOT NULL,
		egress	INTEGER NOT NULL,
		path	BLOB,
		end_props	INTEGER NOT NULL,
		traffic_split	INTEGER NOT NULL,
		src_ia INTEGER,
		dst_ia INTEGER,
		active_index	INTEGER NOT NULL,
		PRIMARY KEY(ROWID),
		UNIQUE(id_as,id_suffix),
		UNIQUE(path)
	);
	CREATE TABLE seg_index (
		reservation	INTEGER NOT NULL,
		index_number	INTEGER NOT NULL,
		expiration	INTEGER NOT NULL,
		state	INTEGER NOT NULL,
		min_bw	INTEGER NOT NULL,
		max_bw	INTEGER NOT NULL,
		alloc_bw	INTEGER NOT NULL,
		token	BLOB,
		PRIMARY KEY(reservation,index_number),
		FOREIGN KEY(reservation) REFERENCES seg_reservation(ROWID) ON DELETE CASCADE
	);
	CREATE TABLE e2e_reservation (
		ROWID	INTEGER,
		reservation_id	BLOB NOT NULL,
		UNIQUE(reservation_id),
		PRIMARY KEY(ROWID)
	);
	CREATE TABLE e2e_index (
		reservation	INTEGER NOT NULL,
		index_number	INTEGER NOT NULL,
		expiration	INTEGER NOT NULL,
		alloc_bw	INTEGER NOT NULL,
		token	BLOB,
		PRIMARY KEY(reservation,index_number),
		FOREIGN KEY(reservation) REFERENCES e2e_reservation(ROWID) ON DELETE CASCADE
	);
	CREATE TABLE e2e_to_seg (
		e2e	INTEGER NOT NULL,
		seg	INTEGER NOT NULL,
		PRIMARY KEY(e2e,seg),
		FOREIGN KEY(seg) REFERENCES seg_reservation(ROWID) ON DELETE CASCADE,
		FOREIGN KEY(e2e) REFERENCES e2e_reservation(ROWID) ON DELETE CASCADE
	);
	CREATE INDEX "index_seg_reservation" ON "seg_reservation" (
		"id_as",
		"id_suffix"
	);
	CREATE INDEX "index2_seg_reservation" ON "seg_reservation" (
		"ingress"
	);
	CREATE INDEX "index3_seg_reservation" ON "seg_reservation" (
		"egress"
	);
	CREATE UNIQUE INDEX "index4_seg_reservation" ON "seg_reservation" (
		"path"
	);
	CREATE UNIQUE INDEX "index_seg_index" ON "seg_index" (
		"reservation",
		"index_number"
	);
	CREATE UNIQUE INDEX "index_e2e_reservation" ON "e2e_reservation" (
		"reservation_id"
	);
	CREATE UNIQUE INDEX "index_e2e_index" ON "e2e_index" (
		"reservation",
		"index_number"
	);
	CREATE INDEX "index_e2e_to_seg" ON "e2e_to_seg" (
		"e2e"
	);
	CREATE INDEX "index2_e2e_to_seg" ON "e2e_to_seg" (
		"seg"
	);`
)
