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

package trustdb

import (
	"io/ioutil"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
)

func TestTRC(t *testing.T) {
	Convey("Initialize DB and load TRC", t, func() {
		db, cleanF := newDatabase(t)
		defer cleanF()

		trcobj, err := trc.TRCFromFile("testdata/ISD1-V1.trc", false)
		SoMsg("err trc", err, ShouldBeNil)
		SoMsg("trc", trcobj, ShouldNotBeNil)
		Convey("Insert into database", func() {
			err := db.InsertTRC(1, 10, trcobj)
			SoMsg("err", err, ShouldBeNil)
			Convey("Get TRC from database", func() {
				newTRCobj, err := db.GetTRCVersion(1, 10)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldResemble, trcobj)
			})
			Convey("Get Max TRC from database", func() {
				newTRCobj, err := db.GetTRCMaxVersion(1)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldResemble, trcobj)
			})
			Convey("Get missing TRC from database", func() {
				newTRCobj, err := db.GetTRCVersion(2, 10)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldBeNil)
			})
		})
	})
}

func TestChain(t *testing.T) {
	Convey("Initialize DB and load TRC", t, func() {
		db, cleanF := newDatabase(t)
		defer cleanF()

		trcobj, err := cert.ChainFromFile("testdata/ISD1-AS10-V1.crt", false)
		SoMsg("err trc", err, ShouldBeNil)
		SoMsg("trc", trcobj, ShouldNotBeNil)
		ia := addr.IA{I: 1, A: 1}
		Convey("Insert into database", func() {
			err := db.InsertChain(ia, 10, trcobj)
			SoMsg("err", err, ShouldBeNil)
			Convey("Get certificate chain from database", func() {
				newTRCobj, err := db.GetChainVersion(ia, 10)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldResemble, trcobj)
			})
			Convey("Get max version certificate chain from database", func() {
				newTRCobj, err := db.GetChainMaxVersion(ia)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldResemble, trcobj)
			})
			Convey("Get missing certificate chain from database", func() {
				otherIA := addr.IA{I: 1, A: 2}
				newTRCobj, err := db.GetChainVersion(otherIA, 10)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldBeNil)
			})
		})
	})
}

func newDatabase(t *testing.T) (*DB, func()) {
	file, err := ioutil.TempFile("", "db-test-")
	if err != nil {
		t.Fatalf("unable to create temp file")
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		t.Fatalf("unable to close temp file")
	}
	db, err := New(name)
	if err != nil {
		t.Fatalf("unable to initialize database")
	}
	return db, func() {
		db.Close()
		os.Remove(name)
	}
}
