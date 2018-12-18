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

package trustdbtest

import (
	"context"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	Timeout = time.Second
)

type rwTrustDB interface {
	trustdb.Read
	trustdb.Write
}

// TestTrustDB should be used to test any implementation of the TrustDB interface.
// An implementation of the TrustDB interface should at least have on test method that calls
// this test-suite. The calling test code should have a top level Convey block.
//
// setup should return a TrustDB in a clean state, i.e. no entries in the DB.
// cleanup can be used to release any resources that have been allocated during setup.
func TestTrustDB(t *testing.T, setup func() trustdb.TrustDB, cleanup func(trustdb.TrustDB)) {
	testWrapper := func(test func(*testing.T, rwTrustDB)) func() {
		return func() {
			db := setup()
			test(t, db)
			cleanup(db)
		}
	}
	Convey("TestTRC", testWrapper(testTRC))
	Convey("TestTRCGetAll", testWrapper(testTRCGetAll))
	Convey("TestIssCert", testWrapper(testIssCert))
	Convey("TestLeafCert", testWrapper(testLeafCert))
	Convey("TestChain", testWrapper(testChain))
	Convey("TestChainGetAll", testWrapper(testChainGetAll))
	Convey("TestCustKey", testWrapper(testCustKey))
	// Now test everything with a transaction as well.
	txTestWrapper := func(test func(*testing.T, rwTrustDB)) func() {
		return func() {
			ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
			defer cancelF()
			db := setup()
			tx, err := db.BeginTransaction(ctx, nil)
			xtest.FailOnErr(t, err)
			test(t, tx)
			err = tx.Commit()
			xtest.FailOnErr(t, err)
			cleanup(db)
		}
	}
	trustDbTestWrapper := func(test func(*testing.T, trustdb.TrustDB)) func() {
		return func() {
			db := setup()
			test(t, db)
			cleanup(db)
		}
	}
	Convey("WithTransaction", func() {
		Convey("TestTRC", txTestWrapper(testTRC))
		Convey("TestTRCGetAll", txTestWrapper(testTRCGetAll))
		Convey("TestIssCert", txTestWrapper(testIssCert))
		Convey("TestLeafCert", txTestWrapper(testLeafCert))
		Convey("TestChain", txTestWrapper(testChain))
		Convey("TestChainGetAll", txTestWrapper(testChainGetAll))
		Convey("TestCustKey", txTestWrapper(testCustKey))
		Convey("TransactionRollback", trustDbTestWrapper(testRollback))
	})
}

func testTRC(t *testing.T, db rwTrustDB) {
	Convey("Initialize DB and load TRC", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
		defer cancelF()

		trcobj, err := trc.TRCFromFile("../trustdbtest/testdata/ISD1-V1.trc", false)
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

func testTRCGetAll(t *testing.T, db rwTrustDB) {
	Convey("Test get all TRCs", func() {
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

func insertTRCFromFile(t *testing.T, ctx context.Context,
	fName string, db rwTrustDB) *trc.TRC {

	trcobj, err := trc.TRCFromFile("../trustdbtest/"+fName, false)
	xtest.FailOnErr(t, err)
	_, err = db.InsertTRC(ctx, trcobj)
	xtest.FailOnErr(t, err)
	return trcobj
}

func testIssCert(t *testing.T, db rwTrustDB) {
	Convey("Initialize DB and load issuer Cert", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
		defer cancelF()

		chain, err := cert.ChainFromFile("../trustdbtest/testdata/ISD1-ASff00_0_311-V1.crt", false)
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

func testLeafCert(t *testing.T, db rwTrustDB) {
	Convey("Initialize DB and load leaf Cert", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
		defer cancelF()

		chain, err := cert.ChainFromFile("../trustdbtest/testdata/ISD1-ASff00_0_311-V1.crt", false)
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

func testChain(t *testing.T, db rwTrustDB) {
	Convey("Initialize DB and load Chain", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
		defer cancelF()

		chain, err := cert.ChainFromFile("../trustdbtest/testdata/ISD1-ASff00_0_311-V1.crt", false)
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

func testChainGetAll(t *testing.T, db rwTrustDB) {
	Convey("Test get all chains", func() {
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

func testCustKey(t *testing.T, db rwTrustDB) {
	Convey("Cust Key tests on an emptry trust db", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
		defer cancelF()

		ia1_110 := xtest.MustParseIA("1-ff00:0:110")
		key_110_1 := common.RawBytes("dddddddd")
		key_110_2 := common.RawBytes("ddddddaa")

		Convey("GetCustKey should return nil and no error", func() {
			key, ver, err := db.GetCustKey(ctx, ia1_110)
			SoMsg("No error expected", err, ShouldBeNil)
			SoMsg("Empty result expected", key, ShouldBeNil)
			SoMsg("0 version expected", ver, ShouldEqual, 0)
		})
		Convey("Insertion should work without error", func() {
			var ver uint64 = 1
			err := db.InsertCustKey(ctx, ia1_110, ver, key_110_1, 0)
			SoMsg("No error expected", err, ShouldBeNil)
			Convey("Inserted entry should be returned", func() {
				key, dbVer, err := db.GetCustKey(ctx, ia1_110)
				SoMsg("No error expected", err, ShouldBeNil)
				SoMsg("Inserted key expected", key, ShouldResemble, key_110_1)
				SoMsg("Inserted version expected", dbVer, ShouldEqual, ver)
			})
			Convey("Inserting a newer version should work", func() {
				var newVer uint64 = 2
				err := db.InsertCustKey(ctx, ia1_110, newVer, key_110_2, ver)
				SoMsg("No error expected", err, ShouldBeNil)
				Convey("New version should be returned", func() {
					key, dbVer, err := db.GetCustKey(ctx, ia1_110)
					SoMsg("No error expected", err, ShouldBeNil)
					SoMsg("Inserted key expected", key, ShouldResemble, key_110_2)
					SoMsg("Inserted version expected", dbVer, ShouldEqual, newVer)
				})
			})
			Convey("Inserting the same version again should error", func() {
				err := db.InsertCustKey(ctx, ia1_110, ver, key_110_2, ver)
				SoMsg("Error expected", err, ShouldNotBeNil)
			})
			Convey("Inserting with 0 version should fail if there is an entry", func() {
				err := db.InsertCustKey(ctx, ia1_110, ver, key_110_1, 0)
				SoMsg("Error expected", err, ShouldNotBeNil)
			})
			Convey("Updating with outdated old version should fail", func() {
				var newVer uint64 = 2
				err := db.InsertCustKey(ctx, ia1_110, newVer, key_110_2, ver)
				SoMsg("No error expected", err, ShouldBeNil)
				err = db.InsertCustKey(ctx, ia1_110, newVer, key_110_2, ver)
				SoMsg("Error expected", err, ShouldNotBeNil)
			})
		})
	})
}

func testRollback(t *testing.T, db trustdb.TrustDB) {
	Convey("Test transaction rollback", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		tx, err := db.BeginTransaction(ctx, nil)
		SoMsg("Transaction begin should not fail", err, ShouldBeNil)
		trcobj, err := trc.TRCFromFile("../trustdbtest/testdata/ISD1-V1.trc", false)
		SoMsg("err trc", err, ShouldBeNil)
		SoMsg("trc", trcobj, ShouldNotBeNil)
		cnt, err := tx.InsertTRC(ctx, trcobj)
		SoMsg("TRC insert should not fail", err, ShouldBeNil)
		SoMsg("Insert count", cnt, ShouldEqual, 1)
		err = tx.Rollback()
		SoMsg("Rollback should not fail", err, ShouldBeNil)
		trcs, err := db.GetAllTRCs(ctx)
		SoMsg("GetAllTRCs should work", err, ShouldBeNil)
		SoMsg("No TRCs expected", len(trcs), ShouldEqual, 0)
	})
}

func insertChainFromFile(t *testing.T, ctx context.Context,
	fName string, db rwTrustDB) *cert.Chain {

	chain, err := cert.ChainFromFile("../trustdbtest/"+fName, false)
	xtest.FailOnErr(t, err)
	_, err = db.InsertChain(ctx, chain)
	xtest.FailOnErr(t, err)
	return chain
}
