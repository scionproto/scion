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

package trustdb

import (
	"context"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	ctxTimeout = time.Second
)

func TestTRC(t *testing.T) {
	Convey("Initialize DB and load TRC", t, func() {
		db := newDatabase(t)
		defer db.Close()
		ctx, cancelF := context.WithTimeout(context.Background(), ctxTimeout)
		defer cancelF()

		trcobj, err := trc.TRCFromFile("testdata/ISD1-V1.trc", false)
		SoMsg("err trc", err, ShouldBeNil)
		SoMsg("trc", trcobj, ShouldNotBeNil)
		Convey("Insert into database", func() {
			rows, err := db.InsertTRC(ctx, trcobj)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldNotEqual, 0)
			rows, err = db.InsertTRC(ctx, trcobj)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 0)
			Convey("Get TRC from database", func() {
				newTRCobj, err := db.GetTRCVersion(ctx, 1, 1)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldResemble, trcobj)
			})
			Convey("Get Max TRC from database", func() {
				newTRCobj, err := db.GetTRCMaxVersion(ctx, 1)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldResemble, trcobj)
				newTRCobj, err = db.GetTRCVersion(ctx, 1, scrypto.LatestVer)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldResemble, trcobj)
			})
			Convey("Get missing TRC from database", func() {
				newTRCobj, err := db.GetTRCVersion(ctx, 2, 10)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldBeNil)
			})
			Convey("Get missing Max TRC from database", func() {
				newTRCobj, err := db.GetTRCVersion(ctx, 2, scrypto.LatestVer)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldBeNil)
				newTRCobj, err = db.GetTRCMaxVersion(ctx, 2)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("trc", newTRCobj, ShouldBeNil)
			})
		})
	})
}

func TestTRCGetAll(t *testing.T) {
	Convey("Test get all TRCs", t, func() {
		db := newDatabase(t)
		defer db.Close()
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		Convey("GetAllTRCs on empty DB does not fail and returns nil", func() {
			trcs, err := db.GetAllTRCs(ctx)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("trcs", trcs, ShouldBeNil)
		})
		Convey("GetAllTRCs on DB with 1 entry does not fail and returns entry", func() {
			trcObj := insertTRCFromFile(t, ctx, "testdata/ISD1-V1.trc", db)
			trcs, err := db.GetAllTRCs(ctx)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("trcs", trcs, ShouldResemble, []*trc.TRC{trcObj})
		})
		Convey("GetAllTRCs on DB with 2 entries does not fail and returns entries", func() {
			trcObj := insertTRCFromFile(t, ctx, "testdata/ISD1-V1.trc", db)
			trcObj2 := insertTRCFromFile(t, ctx, "testdata/ISD2-V1.trc", db)
			trcs, err := db.GetAllTRCs(ctx)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("trcs", trcs, ShouldResemble, []*trc.TRC{trcObj, trcObj2})
		})
	})
}

func insertTRCFromFile(t *testing.T, ctx context.Context, fName string, db *DB) *trc.TRC {
	trcobj, err := trc.TRCFromFile(fName, false)
	xtest.FailOnErr(t, err)
	_, err = db.InsertTRC(ctx, trcobj)
	xtest.FailOnErr(t, err)
	return trcobj
}

func TestIssCert(t *testing.T) {
	Convey("Initialize DB and load issuer Cert", t, func() {
		db := newDatabase(t)
		defer db.Close()
		ctx, cancelF := context.WithTimeout(context.Background(), ctxTimeout)
		defer cancelF()

		chain, err := cert.ChainFromFile("testdata/ISD1-ASff00_0_311-V1.crt", false)
		if err != nil {
			t.Fatalf("Unable to load certificate chain")
		}
		ia := addr.IA{I: 1, A: 0xff0000000310}
		Convey("Insert into database", func() {
			rows, err := db.InsertIssCert(ctx, chain.Issuer)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldNotEqual, 0)
			rows, err = db.InsertIssCert(ctx, chain.Issuer)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 0)
			Convey("Get issuer certificate from database", func() {
				crt, err := db.GetIssCertVersion(ctx, ia, 1)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldResemble, chain.Issuer)
			})
			Convey("Get max version issuer certificate from database", func() {
				crt, err := db.GetIssCertMaxVersion(ctx, ia)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldResemble, chain.Issuer)
				crt, err = db.GetIssCertVersion(ctx, ia, scrypto.LatestVer)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldResemble, chain.Issuer)
			})
			Convey("Get missing issuer certificate from database", func() {
				otherIA := addr.IA{I: 1, A: 0xff0000000320}
				crt, err := db.GetIssCertVersion(ctx, otherIA, 10)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldBeNil)
			})
			Convey("Get missing issuer max certificate from database", func() {
				otherIA := addr.IA{I: 1, A: 0xff0000000320}
				crt, err := db.GetIssCertVersion(ctx, otherIA, scrypto.LatestVer)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldBeNil)
				crt, err = db.GetIssCertMaxVersion(ctx, otherIA)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldBeNil)
			})
		})
	})
}

func TestLeafCert(t *testing.T) {
	Convey("Initialize DB and load leaf Cert", t, func() {
		db := newDatabase(t)
		defer db.Close()
		ctx, cancelF := context.WithTimeout(context.Background(), ctxTimeout)
		defer cancelF()

		chain, err := cert.ChainFromFile("testdata/ISD1-ASff00_0_311-V1.crt", false)
		if err != nil {
			t.Fatalf("Unable to load certificate chain")
		}
		ia := addr.IA{I: 1, A: 0xff0000000311}
		Convey("Insert into database", func() {
			rows, err := db.InsertLeafCert(ctx, chain.Leaf)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldNotEqual, 0)
			rows, err = db.InsertLeafCert(ctx, chain.Leaf)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 0)
			Convey("Get leaf certificate from database", func() {
				crt, err := db.GetLeafCertVersion(ctx, ia, 1)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldResemble, chain.Leaf)
			})
			Convey("Get max version leaf certificate from database", func() {
				crt, err := db.GetLeafCertMaxVersion(ctx, ia)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldResemble, chain.Leaf)
				crt, err = db.GetLeafCertVersion(ctx, ia, scrypto.LatestVer)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldResemble, chain.Leaf)
			})
			Convey("Get missing leaf certificate from database", func() {
				otherIA := addr.IA{I: 1, A: 0xff0000000321}
				crt, err := db.GetLeafCertVersion(ctx, otherIA, 10)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldBeNil)
			})
			Convey("Get missing leaf max certificate from database", func() {
				otherIA := addr.IA{I: 1, A: 0xff0000000321}
				crt, err := db.GetLeafCertVersion(ctx, otherIA, scrypto.LatestVer)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldBeNil)
				crt, err = db.GetLeafCertMaxVersion(ctx, otherIA)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldBeNil)
			})
		})
	})
}

func TestChain(t *testing.T) {
	Convey("Initialize DB and load Chain", t, func() {
		db := newDatabase(t)
		defer db.Close()
		ctx, cancelF := context.WithTimeout(context.Background(), ctxTimeout)
		defer cancelF()

		chain, err := cert.ChainFromFile("testdata/ISD1-ASff00_0_311-V1.crt", false)
		xtest.FailOnErr(t, err)
		ia := addr.IA{I: 1, A: 0xff0000000311}
		Convey("Insert into database", func() {
			rows, err := db.InsertChain(ctx, chain)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldNotEqual, 0)
			Convey("Get certificate chain from database", func() {
				newChain, err := db.GetChainVersion(ctx, ia, 1)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("chain", newChain, ShouldResemble, chain)
			})
			Convey("Get max version certificate chain from database", func() {
				newChain, err := db.GetChainMaxVersion(ctx, ia)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("chain", newChain, ShouldResemble, chain)
				newChain, err = db.GetChainVersion(ctx, ia, scrypto.LatestVer)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("chain", newChain, ShouldResemble, chain)
			})
			Convey("Get missing certificate chain from database", func() {
				otherIA := addr.IA{I: 1, A: 0xff0000000320}
				newChain, err := db.GetChainVersion(ctx, otherIA, 10)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("chain", newChain, ShouldBeNil)
			})
			Convey("Get missing max certificate chain from database", func() {
				otherIA := addr.IA{I: 1, A: 0xff0000000320}
				newChain, err := db.GetChainVersion(ctx, otherIA, scrypto.LatestVer)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("chain", newChain, ShouldBeNil)
				newChain, err = db.GetChainMaxVersion(ctx, otherIA)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("chain", newChain, ShouldBeNil)
			})
		})
	})
}

func TestChainGetAll(t *testing.T) {
	Convey("Test get all chains", t, func() {
		db := newDatabase(t)
		defer db.Close()
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		Convey("GetAllChains on empty DB does not fails and return nil", func() {
			chains, err := db.GetAllChains(ctx)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("chains", chains, ShouldBeNil)
		})
		Convey("GetAllChains on DB with 1 entry does not fails and returns entry", func() {
			chain := insertChainFromFile(t, ctx, "testdata/ISD1-ASff00_0_311-V1.crt", db)
			chains, err := db.GetAllChains(ctx)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("chains", chains, ShouldResemble, []*cert.Chain{chain})
		})
		Convey("GetAllChains on DB with 2 entries does not fails and returns entries", func() {
			chain := insertChainFromFile(t, ctx, "testdata/ISD1-ASff00_0_311-V1.crt", db)
			chain2 := insertChainFromFile(t, ctx, "testdata/ISD2-ASff00_0_212-V1.crt", db)
			chains, err := db.GetAllChains(ctx)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("chains", chains, ShouldResemble, []*cert.Chain{chain, chain2})
		})
	})
}

func insertChainFromFile(t *testing.T, ctx context.Context, fName string, db *DB) *cert.Chain {
	chain, err := cert.ChainFromFile(fName, false)
	xtest.FailOnErr(t, err)
	_, err = db.InsertChain(ctx, chain)
	xtest.FailOnErr(t, err)
	return chain
}

func newDatabase(t *testing.T) *DB {
	db, err := New(":memory:")
	xtest.FailOnErr(t, err)
	return db
}
