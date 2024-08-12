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

package db

import (
	"database/sql"
	"fmt"
	"net/url"

	"github.com/scionproto/scion/pkg/private/serrors"
)

const _ = buildtag_guard_either_sqlite_mattn_or_sqlite_modernc

// NewSqlite returns a new SQLite backend opening a database at the given path. If
// no database exists a new database is be created. If the schema version of the
// stored database is different from schemaVersion, an error is returned.
func NewSqlite(path string, schema string, schemaVersion int) (*sql.DB, error) {
	var err error
	if path == "" {
		return nil, serrors.New("Empty path not allowed for sqlite")
	}
	db, err := open(path)
	if err != nil {
		return nil, err
	}
	// On future errors, close the sql database before exiting
	defer func() {
		if err != nil {
			db.Close()
		}
	}()
	// prevent weird errors. (see https://stackoverflow.com/a/35805826)
	db.SetMaxOpenConns(1)
	// Check the schema version and set up new DB if necessary.
	var existingVersion int
	err = db.QueryRow("PRAGMA user_version;").Scan(&existingVersion)
	if err != nil {
		return nil, serrors.Wrap("Failed to check schema version", err,
			"path", path)

	}
	if existingVersion == 0 {
		if err = setup(db, schema, schemaVersion, path); err != nil {
			return nil, err
		}
	} else if existingVersion != schemaVersion {
		return nil, serrors.New("Database schema version mismatch",
			"expected", schemaVersion, "have", existingVersion, "path", path)
	}
	return db, nil
}

func open(path string) (*sql.DB, error) {
	var err error
	u, err := url.Parse(path)
	if err != nil {
		return nil, serrors.Wrap("invalid connection path", err, "path", path)

	}
	// Add foreign_key parameter to path to enable foreign key support.
	q := u.Query()
	addPragmas(q)
	u.RawQuery = q.Encode()
	path = u.String()
	db, err := sql.Open(driverName(), path)
	if err != nil {
		return nil, serrors.Wrap("Couldn't open SQLite database", err, "path", path)
	}
	// On future errors, close the sql database before exiting
	defer func() {
		if err != nil {
			db.Close()
		}
	}()
	// Make sure DB is reachable
	if err = db.Ping(); err != nil {
		return nil, serrors.Wrap("Initial DB ping failed, connection broken?", err,
			"path", path)

	}
	// Ensure foreign keys are supported and enabled.
	var enabled bool
	err = db.QueryRow("PRAGMA foreign_keys;").Scan(&enabled)
	if err == sql.ErrNoRows {
		return nil, serrors.Wrap("Foreign keys not supported", err,
			"path", path)

	}
	if err != nil {
		return nil, serrors.Wrap("Failed to check for foreign key support", err,
			"path", path)

	}
	if !enabled {
		db.Close()
		return nil, serrors.New("Failed to enable foreign key support",
			"path", path)
	}
	return db, nil
}

func setup(db *sql.DB, schema string, schemaVersion int, path string) error {
	_, err := db.Exec(schema)
	if err != nil {
		return serrors.Wrap("Failed to set up SQLite database", err, "path", path)
	}
	// Write schema version to database.
	_, err = db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion))
	if err != nil {
		return serrors.Wrap("Failed to write schema version", err, "path", path)
	}
	return nil
}
