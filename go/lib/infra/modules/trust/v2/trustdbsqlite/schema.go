// Copyright 2019 Anapaya Systems
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
	SchemaVersion = 1
	// Schema is the SQLite database layout.
	Schema = `
	CREATE TABLE trcs(
		isd_id INTEGER NOT NULL,
		version INTEGER NOT NULL,
		raw DATA NOT NULL,
		pld DATA NOT NULL,
		pld_hash DATA NOT NULL,
		not_before INTEGER NOT NULL,
		not_after INTEGER NOT NULL,
		grace_period INTEGER NOT NULL,
		PRIMARY KEY (isd_id, version)
	);
	CREATE TABLE chains(
		isd_id INTEGER NOT NULL,
		as_id INTEGER NOT NULL,
		version INTEGER NOT NULL,
		raw DATA NOT NULL,
		as_hash DATA NOT NULL,
		issuer_hash DATA NOT NULL,
		PRIMARY KEY (isd_id, as_id, version)
	);
	CREATE TABLE issuer_certs(
		isd_id INTEGER NOT NULL,
		as_id INTEGER NOT NULL,
		version INTEGER NOT NULL,
		pld DATA NOT NULL,
		pld_hash DATA NOT NULL,
		protected DATA NOT NULL,
		signature DATA NOT NULL,
		PRIMARY KEY (isd_id, as_id, version)
	);
	`
)
