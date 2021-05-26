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

package sqlite

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/pathdb/pathdbtest"
	"github.com/scionproto/scion/go/lib/pathdb/query"
)

var (
	ia330    = addr.IA{I: 1, A: 0xff0000000330}
	ifs1     = []uint64{0, 5, 2, 3, 6, 3, 1, 0}
	hpCfgIDs = []*query.HPCfgID{
		&query.NullHpCfgID,
		{IA: ia330, ID: 0xdeadbeef},
	}
	timeout = time.Second
)

var _ pathdbtest.TestablePathDB = (*TestPathDB)(nil)

type TestPathDB struct {
	*Backend
}

func (b *TestPathDB) Prepare(t *testing.T, _ context.Context) {
	db, err := New("file::memory:")
	require.NoError(t, err)
	b.Backend = db
}

func TestPathDBSuite(t *testing.T) {
	tdb := &TestPathDB{}
	pathdbtest.TestPathDB(t, tdb)
}

// TestOpenExisting tests that New does not overwrite an existing database if
// versions match.
func TestOpenExisting(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	b, tmpF := setupDB(t)
	defer cleanup(tmpF)
	TS := uint32(10)
	pseg1, _ := pathdbtest.AllocPathSegment(t, ctrl, ifs1, TS)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pathdbtest.InsertSeg(t, ctx, b, pseg1, hpCfgIDs)
	b.db.Close()
	// Call
	b, err := New(tmpF)
	require.NoError(t, err)
	// Test
	// Check that path segment is still there.
	ctx, cancelF = context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	res, err := b.Get(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, len(res), "Segment still exists")
}

// TestOpenNewer tests that New does not overwrite an existing database if it's
// of a newer version.
func TestOpenNewer(t *testing.T) {
	b, tmpF := setupDB(t)
	defer cleanup(tmpF)
	// Write a newer version
	_, err := b.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion+1))
	require.NoError(t, err)
	b.db.Close()
	// Call
	b, err = New(tmpF)
	// Test
	assert.Error(t, err)
	assert.Nil(t, b)
}

func setupDB(t *testing.T) (*Backend, string) {
	tmpFile := tempFilename(t)
	b, err := New(tmpFile)
	require.NoError(t, err, "Failed to open DB")
	return b, tmpFile
}

func tempFilename(t *testing.T) string {
	dir, err := ioutil.TempDir("", "pathdb-sqlite")
	require.NoError(t, err)
	return path.Join(dir, t.Name())
}

func cleanup(tmpFile string) {
	os.RemoveAll(filepath.Dir(tmpFile))
}
