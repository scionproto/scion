// Copyright 2023 SCION Association
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

//go:build sqlite_mattn

package db

import (
	"net/url"

	_ "github.com/mattn/go-sqlite3"
)

const buildtag_guard_either_sqlite_mattn_or_sqlite_modernc = "must choose an sqlite " +
	"implementation to build, by defining exactly one of the gotags " +
	"'sqlite_modernc' or 'sqlite_mattn'"

// addPragmas() modifies given URL query so it can be used to make the correct uri
// connection path for this sqlite implementation. The modifications turn on
// foreign keys and WAL journal mode for every SQL query.
func addPragmas(q url.Values) {
	// Add foreign_key parameter to path to enable foreign key support.
	q.Set("_foreign_keys", "1")
	// prevent weird errors. (see https://stackoverflow.com/a/35805826)
	q.Set("_journal_mode", "WAL")
}

func driverName() string {
	return "sqlite3"
}
