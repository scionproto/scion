// Copyright 2020 Anapaya Systems
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
	Schema = `
	CREATE TABLE chains(
		isd_id INTEGER NOT NULL,
		as_id INTEGER NOT NULL,
		key_id DATA NOT NULL,
		not_before INTEGER NOT NULL,
		not_after INTEGER NOT NULL,
		chain_fingerprint DATA NOT NULL,
		as_cert DATA NOT NULL,
		ca_cert DATA NOT NULL,
		PRIMARY KEY (isd_id, as_id, key_id, not_before, not_after, chain_fingerprint)
	);
	CREATE TABLE trcs(
		isd_id INTEGER NOT NULL,
		base INTEGER NOT NULL,
		serial INTEGER NOT NULL,
		fingerprint DATA NOT NULL,
		trc DATA NOT NULL,
		PRIMARY KEY (isd_id, base, serial)
	);
	`
)
