// Copyright 2018 ETH Zurich
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

import (
	"database/sql"
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
)

// New returns a new SQLite backend opening a database at the given path. If
// no database exists a new database is be created. If the schema version of the
// stored database is different from schemaVersion, an error is returned.
func New(path string, schema string, schemaVersion int) (*sql.DB, error) {
	db, err := open(path)
	if err != nil {
		return nil, err
	}
	// Check the schema version and set up new DB if necessary.
	var existingVersion int
	err = db.QueryRow("PRAGMA user_version;").Scan(&existingVersion)
	if err != nil {
		return nil, common.NewBasicError("Failed to check schema version", err)
	}
	if existingVersion == 0 {
		if err := setup(db, schema, schemaVersion); err != nil {
			return nil, err
		}
	} else if existingVersion != schemaVersion {
		return nil, common.NewBasicError("Database schema version mismatch", nil,
			"expected", schemaVersion, "have", existingVersion)
	}
	return db, nil
}

func open(path string) (*sql.DB, error) {
	// Add foreign_key parameter to path to enable foreign key support.
	uri := fmt.Sprintf("%s?_foreign_keys=1", path)
	var err error
	db, err := sql.Open("sqlite3", uri)
	if err != nil {
		return nil, common.NewBasicError("Couldn't open SQLite database", err)
	}
	// Ensure foreign keys are supported and enabled.
	var enabled bool
	err = db.QueryRow("PRAGMA foreign_keys;").Scan(&enabled)
	if err == sql.ErrNoRows {
		return nil, common.NewBasicError("Foreign keys not supported", err)
	}
	if err != nil {
		return nil, common.NewBasicError("Failed to check for foreign key support", err)
	}
	if !enabled {
		return nil, common.NewBasicError("Failed to enable foreign key support", nil)
	}
	return db, nil
}

func setup(db *sql.DB, schema string, schemaVersion int) error {
	if db == nil {
		return common.NewBasicError("No database open", nil)
	}
	_, err := db.Exec(schema)
	if err != nil {
		return common.NewBasicError("Failed to set up SQLite database", err, "err", err)
	}
	// Write schema version to database.
	_, err = db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion))
	if err != nil {
		return common.NewBasicError("Failed to write schema version", err)
	}
	return nil
}
