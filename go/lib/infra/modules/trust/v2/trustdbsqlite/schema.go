// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

// This file contains an SQLite backend for the trust database.

package trustdbsqlite

const (
	// SchemaVersion is the version of the SQLite schema understood by this backend.
	// Whenever changes to the schema are made, this version number should be increased
	// to prevent data corruption between incompatible database schemas.
	SchemaVersion = 8
	// Schema is the SQLite database layout.
	Schema = `
	CREATE TABLE TRCs(
		IsdID INTEGER NOT NULL,
		Version INTEGER NOT NULL,
		Raw DATA NOT NULL,
		Pld DATA NOT NULL,
		PldHash DATA NOT NULL,
		NotBefore INTEGER NOT NULL,
		NotAfter INTEGER NOT NULL,
		GracePeriod INTEGER NOT NULL,
		PRIMARY KEY (IsdID, Version)
	);
	CREATE TABLE Chains(
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		Version INTEGER NOT NULL,
		Raw DATA NOT NULL,
		AsHash DATA NOT NULL,
		IssuerHash DATA NOT NULL,
		PRIMARY KEY (IsdID, AsID, Version)
	);
	CREATE TABLE IssuerCerts(
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		Version INTEGER NOT NULL,
		Pld DATA NOT NULL,
		PldHash DATA NOT NULL,
		Protected DATA NOT NULL,
		Signature DATA NOT NULL,
		PRIMARY KEY (IsdID, AsID, Version)
	);
	`
	TRCsTable = "TRCs"
)
