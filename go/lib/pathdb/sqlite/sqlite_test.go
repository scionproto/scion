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
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/pathdb/pathdbtest"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

var (
	ia330    = addr.IA{I: 1, A: 0xff0000000330}
	ifs1     = []uint64{0, 5, 2, 3, 6, 3, 1, 0}
	hpCfgIDs = []*query.HPCfgID{
		&query.NullHpCfgID,
		{ia330, 0xdeadbeef},
	}
	segType = proto.PathSegType_up
	timeout = time.Second
)

var _ pathdbtest.TestablePathDB = (*TestPathDB)(nil)

type TestPathDB struct {
	*Backend
}

func (b *TestPathDB) Prepare(t *testing.T, _ context.Context) {
	db, err := New(":memory:")
	xtest.FailOnErr(t, err)
	b.Backend = db
}

func TestPathDBSuite(t *testing.T) {
	tdb := &TestPathDB{}
	Convey("PathDBSuite", t, func() {
		pathdbtest.TestPathDB(t, tdb)
	})
}

func TestOpenExisting(t *testing.T) {
	Convey("New should not overwrite an existing database if versions match", t, func() {
		b, tmpF := setupDB(t)
		defer os.Remove(tmpF)
		TS := uint32(10)
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		pseg1, _ := pathdbtest.AllocPathSegment(t, ifs1, TS)
		pathdbtest.InsertSeg(t, ctx, b, pseg1, hpCfgIDs)
		b.db.Close()
		// Call
		b, err := New(tmpF)
		xtest.FailOnErr(t, err)
		// Test
		// Check that path segment is still there.
		res, err := b.Get(ctx, nil)
		xtest.FailOnErr(t, err)
		SoMsg("Segment still exists", len(res), ShouldEqual, 1)
	})
}

func TestOpenNewer(t *testing.T) {
	Convey("New should not overwrite an existing database if it's of a newer version", t, func() {
		b, tmpF := setupDB(t)
		defer os.Remove(tmpF)
		// Write a newer version
		_, err := b.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion+1))
		xtest.FailOnErr(t, err)
		b.db.Close()
		// Call
		b, err = New(tmpF)
		// Test
		SoMsg("Backend nil", b, ShouldBeNil)
		SoMsg("Err returned", err, ShouldNotBeNil)
	})
}

func setupDB(t *testing.T) (*Backend, string) {
	tmpFile := tempFilename(t)
	b, err := New(tmpFile)
	xtest.FailOnErr(t, err, "Failed to open DB")
	return b, tmpFile
}

func tempFilename(t *testing.T) string {
	dir, err := ioutil.TempDir("", "pathdb-sqlite")
	xtest.FailOnErr(t, err)
	return path.Join(dir, t.Name())
}
