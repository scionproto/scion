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

package sqlite_test

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beacon/beacondbtest"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/private/storage/beacon/dbtest"
	"github.com/scionproto/scion/private/storage/beacon/sqlite"
)

var testIA = addr.MustParseIA("1-ff00:0:333")

type TestBackend struct {
	*sqlite.Backend
}

func (b *TestBackend) Prepare(t *testing.T, _ context.Context) {
	db, err := sqlite.New("file::memory:", testIA)
	require.NoError(t, err)
	b.Backend = db
}

func TestBeaconDBSuite(t *testing.T) {
	tdb := &TestBackend{}
	dbtest.Run(t, tdb)
}

// TestOpenExisting tests that New does not overwrite an existing database if
// versions match.
func TestOpenExisting(t *testing.T) {
	db, tmpF := setupDB(t)
	defer cleanup(tmpF)
	b := beacondbtest.InsertBeacon(t, db, beacondbtest.Info1, 2, 10, beacon.UsageProp)
	db.Close()
	// Open existing database
	db, err := sqlite.New(tmpF, testIA)
	require.NoError(t, err)
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	res, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, 0)
	require.NoError(t, err)

	beacondbtest.CheckResult(t, res, b)
}

// TestOpenNewer tests that New does not overwrite an existing database if it's
// of a newer version.
func TestOpenNewer(t *testing.T) {
	b, tmpF := setupDB(t)
	defer cleanup(tmpF)
	// Write a newer version
	_, err := b.DB().Exec(fmt.Sprintf("PRAGMA user_version = %d", sqlite.SchemaVersion+1))
	require.NoError(t, err)
	b.DB().Close()
	b, err = sqlite.New(tmpF, testIA)
	assert.Error(t, err)
	assert.Nil(t, b)
}

func setupDB(t *testing.T) (*sqlite.Backend, string) {
	tmpFile := tempFilename(t)
	b, err := sqlite.New(tmpFile, testIA)
	require.NoError(t, err, "Failed to open DB")
	return b, tmpFile
}

func tempFilename(t *testing.T) string {
	dir, err := os.MkdirTemp("", "beacondb-sqlite")
	require.NoError(t, err)
	return path.Join(dir, t.Name())
}

func cleanup(tmpFile string) {
	os.RemoveAll(filepath.Dir(tmpFile))
}
