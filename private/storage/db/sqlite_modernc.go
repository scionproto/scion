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

//go:build sqlite_modernc || !sqlite_mattn

// Note that above go:build expression makes modernc the default by matching
// the absence of sqlite_mattn. Should there be more alternatives, please
// update that expression to match their absence too.
// Also note that this default is overridden by a build configuration
// in .bazelrc, so this is only useful when building with "go build" and
// may not match the bazel build configuration.

package db

import (
	"net/url"

	_ "modernc.org/sqlite"
)

const buildtag_guard_either_sqlite_mattn_or_sqlite_modernc = "must choose an sqlite " +
	"implementation to build, by defining exactly one of the gotags " +
	"'sqlite_modernc' or 'sqlite_mattn'"

// addPragmas() modifies given URL query so it can be used to make the correct uri
// connection path for this sqlite implementation. The modifications turn on
// foreign keys and WAL journal mode for every SQL query.
func addPragmas(q url.Values) {
	// Add foreign_key parameter to path to enable foreign key support.
	q.Add("_pragma", "foreign_keys=1")
	// prevent weird errors. (see https://stackoverflow.com/a/35805826)
	q.Add("_pragma", "journal_mode=WAL")
}

func driverName() string {
	return "sqlite"
}
