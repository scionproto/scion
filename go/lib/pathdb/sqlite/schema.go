// Copyright 2017 ETH Zurich
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

// This file contains an SQLite backend for the PathDB.

package sqlite

const (
	// SchemaVersion is the version of the SQLite schema understood by this backend.
	// Whenever changes to the schema are made, this version number should be increased
	// to prevent data corruption between incompatible database schemas.
	SchemaVersion = 1
	// Schema is the SQLite database layout.
	Schema = `CREATE TABLE Segments(
		RowID INTEGER PRIMARY KEY AUTOINCREMENT,
		SegID DATA UNIQUE NOT NULL,
		LastUpdated INTEGER NOT NULL,
		Segment DATA NOT NULL
	);
	CREATE TABLE IntfToSeg(
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		IntfID INTEGER NOT NULL,
		SegRowID INTEGER NOT NULL,
		FOREIGN KEY (SegRowID) REFERENCES Segments(RowID) ON DELETE CASCADE
	);
	CREATE TABLE StartsAt(
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		SegRowID INTEGER NOT NULL,
		FOREIGN KEY (SegRowID) REFERENCES Segments(RowID) ON DELETE CASCADE
	);
	CREATE TABLE EndsAt(
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		SegRowID INTEGER NOT NULL,
		FOREIGN KEY (SegRowID) REFERENCES Segments(RowID) ON DELETE CASCADE
	);
	CREATE TABLE SegTypes(
		SegRowID INTEGER NOT NULL,
		Type INTEGER NOT NULL,
		PRIMARY KEY (SegRowID, Type) ON CONFLICT IGNORE,
		FOREIGN KEY (SegRowID) REFERENCES Segments(RowID) ON DELETE CASCADE
	);
	CREATE TABLE HpCfgIds(
		SegRowID INTEGER NOT NULL,
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		CfgID INTEGER NOT NULL,
		PRIMARY KEY (SegRowID, IsdID, AsID, CfgID) ON CONFLICT IGNORE,
		FOREIGN KEY (SegRowID) REFERENCES Segments(RowID) ON DELETE CASCADE
	);`
	SegmentsTable  = "Segments"
	IntfToSegTable = "IntfToSeg"
	StartsAtTable  = "StartsAt"
	EndsAtTable    = "EndsAt"
	SegTypesTable  = "SegTypes"
	HpCfgIdsTable  = "HpCfgIds"
)
