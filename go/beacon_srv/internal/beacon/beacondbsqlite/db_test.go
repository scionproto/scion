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

package beacondbsqlite

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/beacon_srv/internal/beacon/beacondbtest"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/xtest"
)

var testIA = addr.IA{I: 1, A: 0xff0000000333}

var _ beacondbtest.Testable = (*TestBackend)(nil)

type TestBackend struct {
	*Backend
}

func (b *TestBackend) Prepare(t *testing.T, _ context.Context) {
	db, err := New(":memory:", testIA)
	xtest.FailOnErr(t, err)
	b.Backend = db
}

func TestBeaconDBSuite(t *testing.T) {
	tdb := &TestBackend{}
	Convey("BeaconDBSuite", t, func() {
		beacondbtest.Test(t, tdb)
	})
}

func TestOpenExisting(t *testing.T) {
	Convey("New should not overwrite an existing database if versions match", t, func() {
		db, tmpF := setupDB(t)
		defer os.Remove(tmpF)
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		b := beacondbtest.InsertBeacon(t, db, beacondbtest.Info1, 2, 10, beacon.UsageProp)
		db.Close()
		// Open existing database
		db, err := New(tmpF, testIA)
		xtest.FailOnErr(t, err)
		res, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp)
		SoMsg("err", err, ShouldBeNil)
		beacondbtest.CheckResult(t, res, b)
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
		b, err = New(tmpF, testIA)
		SoMsg("Backend nil", b, ShouldBeNil)
		SoMsg("Err returned", err, ShouldNotBeNil)
	})
}

func setupDB(t *testing.T) (*Backend, string) {
	tmpFile := tempFilename(t)
	b, err := New(tmpFile, testIA)
	xtest.FailOnErr(t, err, "Failed to open DB")
	return b, tmpFile
}

func tempFilename(t *testing.T) string {
	dir, err := ioutil.TempDir("", "pathdb-sqlite")
	xtest.FailOnErr(t, err)
	return path.Join(dir, t.Name())
}
