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
	"context"
	"io/ioutil"
	"testing"

	log "github.com/inconshreveable/log15"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
)

func TestTRC(t *testing.T) {
	Convey("Initialize DB and load TRC", t, func() {
		db, err := New(randomFileName())
		SoMsg("err db ", err, ShouldBeNil)
		SoMsg("db", db, ShouldNotBeNil)

		trcobj, err := trc.TRCFromFile("testdata/ISD1-V0.trc", false)
		SoMsg("err trc", err, ShouldBeNil)
		SoMsg("trc", trcobj, ShouldNotBeNil)
		Convey("Insert into database", func() {
			rows, err := db.InsertTRC(trcobj)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldNotEqual, 0)
			rows, err = db.InsertTRC(trcobj)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 0)
			Convey("Get TRC from database", func() {
				newTRCobj, err := db.GetTRCVersion(1, 1)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldResemble, trcobj)
			})
			Convey("Get Max TRC from database", func() {
				newTRCobj, err := db.GetTRCMaxVersionCtx(context.Background(), 1)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldResemble, trcobj)
				newTRCobj, err = db.GetTRCVersion(1, 0)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldResemble, trcobj)
			})
			Convey("Get missing TRC from database", func() {
				newTRCobj, err := db.GetTRCVersionCtx(context.Background(), 2, 10)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldBeNil)
			})
			Convey("Get missing Max TRC from database", func() {
				newTRCobj, err := db.GetTRCVersion(2, 0)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldBeNil)
				newTRCobj, err = db.GetTRCMaxVersion(2)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldBeNil)
			})
		})
	})
}

func TestIssCert(t *testing.T) {
	Convey("Initialize DB and load issuer Cert", t, func() {
		db, cleanF := newDatabase(t)
		defer cleanF()

		chain, err := cert.ChainFromFile("testdata/ISD1-ASff00_0_311-V1.crt", false)
		if err != nil {
			t.Fatalf("Unable to load certificate chain")
		}
		ia := addr.IA{I: 1, A: 0xff0000000310}
		Convey("Insert into database", func() {
			rows, err := db.InsertIssCert(chain.Issuer)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldNotEqual, 0)
			rows, err = db.InsertIssCert(chain.Issuer)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 0)
			Convey("Get issuer certificate from database", func() {
				crt, err := db.GetIssCertVersion(ia, 1)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldResemble, chain.Issuer)
			})
			Convey("Get max version issuer certificate from database", func() {
				crt, err := db.GetIssCertMaxVersion(ia)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldResemble, chain.Issuer)
				crt, err = db.GetIssCertVersion(ia, 0)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldResemble, chain.Issuer)
			})
			Convey("Get missing issuer certificate from database", func() {
				otherIA := addr.IA{I: 1, A: 0xff0000000320}
				crt, err := db.GetIssCertVersion(otherIA, 10)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldBeNil)
			})
			Convey("Get missing issuer max certificate from database", func() {
				otherIA := addr.IA{I: 1, A: 0xff0000000320}
				crt, err := db.GetIssCertVersion(otherIA, 0)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldBeNil)
				crt, err = db.GetIssCertMaxVersion(otherIA)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldBeNil)
			})
		})
	})
}

func TestLeafCert(t *testing.T) {
	Convey("Initialize DB and load leaf Cert", t, func() {
		db, cleanF := newDatabase(t)
		defer cleanF()

		chain, err := cert.ChainFromFile("testdata/ISD1-ASff00_0_311-V1.crt", false)
		if err != nil {
			t.Fatalf("Unable to load certificate chain")
		}
		ia := addr.IA{I: 1, A: 0xff0000000311}
		Convey("Insert into database", func() {
			rows, err := db.InsertLeafCert(chain.Leaf)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldNotEqual, 0)
			rows, err = db.InsertLeafCert(chain.Leaf)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 0)
			Convey("Get leaf certificate from database", func() {
				crt, err := db.GetLeafCertVersion(ia, 1)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldResemble, chain.Leaf)
			})
			Convey("Get max version leaf certificate from database", func() {
				crt, err := db.GetLeafCertMaxVersion(ia)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldResemble, chain.Leaf)
				crt, err = db.GetLeafCertVersion(ia, 0)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldResemble, chain.Leaf)
			})
			Convey("Get missing leaf certificate from database", func() {
				otherIA := addr.IA{I: 1, A: 0xff0000000321}
				crt, err := db.GetLeafCertVersion(otherIA, 10)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldBeNil)
			})
			Convey("Get missing leaf max certificate from database", func() {
				otherIA := addr.IA{I: 1, A: 0xff0000000321}
				crt, err := db.GetLeafCertVersion(otherIA, 0)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldBeNil)
				crt, err = db.GetLeafCertMaxVersion(otherIA)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldBeNil)
			})
		})
	})
}

func TestChain(t *testing.T) {
	Convey("Initialize DB and load Chain", t, func() {
		db, cleanF := newDatabase(t)
		defer cleanF()

		chain, err := cert.ChainFromFile("testdata/ISD1-ASff00_0_311-V1.crt", false)
		if err != nil {
			t.Fatalf("Unable to load certificate chain")
		}
		ia := addr.IA{I: 1, A: 0xff0000000311}
		Convey("Insert into database", func() {
			rows, err := db.InsertChain(chain)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldNotEqual, 0)
			Convey("Get certificate chain from database", func() {
				newChain, err := db.GetChainVersion(ia, 1)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("chain", newChain, ShouldResemble, chain)
			})
			Convey("Get max version certificate chain from database", func() {
				newChain, err := db.GetChainMaxVersion(ia)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("chain", newChain, ShouldResemble, chain)
				newChain, err = db.GetChainVersion(ia, 0)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("chain", newChain, ShouldResemble, chain)
			})
			Convey("Get missing certificate chain from database", func() {
				otherIA := addr.IA{I: 1, A: 0xff0000000320}
				newChain, err := db.GetChainVersion(otherIA, 10)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("chain", newChain, ShouldBeNil)
			})
			Convey("Get missing max certificate chain from database", func() {
				otherIA := addr.IA{I: 1, A: 0xff0000000320}
				newChain, err := db.GetChainVersion(otherIA, 0)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("chain", newChain, ShouldBeNil)
				newChain, err = db.GetChainMaxVersion(otherIA)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("chain", newChain, ShouldBeNil)
			})
		})
	})
}

func BenchmarkDB(b *testing.B) {
	// NOTE(scrye): JSON conversion is a 10x drop in performance on my machine.
	// Even so, currently trustdb can serve about 8500 requests per second on a
	// i7 @ 3.4Ghz core.
	logger := log.Root().New("benchmark", "BenchmarkDB")
	db, err := New(randomFileName())
	if err != nil {
		logger.Warn("unable to initialize DB", "err", err)
		return
	}
	trcobj, err := trc.TRCFromFile("testdata/ISD1-V0.trc", false)
	if err != nil {
		logger.Warn("unable to load TRC from file", "err", err)
		return
	}
	if err := db.InsertTRCCtx(context.Background(), 1, 10, trcobj); err != nil {
		logger.Warn("unable to insert TRC in DB", "err", err)
		return
	}
	for i := 0; i < b.N; i++ {
		if _, err := db.GetTRCMaxVersionCtx(context.Background(), 1); err != nil {
			logger.Warn("unable to get max version TRC from DB", "err", err)
			return
		}
	}
}

func BenchmarkDBNoJSON(b *testing.B) {
	logger := log.Root().New("benchmark", "BenchmarkDBNoJSON")
	db, err := New(randomFileName())
	if err != nil {
		logger.Warn("unable to initialize DB", "err", err)
		return
	}
	trcobj, err := trc.TRCFromFile("testdata/ISD1-V0.trc", false)
	if err != nil {
		logger.Warn("unable to load TRC from file", "err", err)
		return
	}
	if err := db.InsertTRCCtx(context.Background(), 1, 10, trcobj); err != nil {
		logger.Warn("unable to insert TRC in DB", "err", err)
		return
	}
	for i := 0; i < b.N; i++ {
		var raw common.RawBytes
		if err := db.getTRCMaxVersionStmt.QueryRow(1).Scan(&raw); err != nil {
			logger.Warn("unable to get max version TRC from DB", "err", err)
			return
		}
	}
}

func randomFileName() string {
	file, err := ioutil.TempFile("", "db-test-")
	if err != nil {
		panic("unable to create temp file")
	}
	name := file.Name()
	err = file.Close()
	if err != nil {
		panic("unable to close temp file")
	}
	return name
}
