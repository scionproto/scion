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
	"fmt"
	"strings"
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
	Timeout         = time.Second
	TestDataRelPath = "../trustdbtest/testdata"
)

// TestableTrustDB extends the trust db interface with methods that are needed for testing.
type TestableTrustDB interface {
	trustdb.TrustDB
	// Prepare should reset the internal state so that the db is empty and is ready to be tested.
	Prepare(*testing.T, context.Context)
}

// TestTrustDB should be used to test any implementation of the TrustDB interface.
// An implementation of the TrustDB interface should at least have on test method that calls
// this test-suite. The calling test code should have a top level Convey block.
//
// setup should return a TrustDB in a clean state, i.e. no entries in the DB.
// cleanup can be used to release any resources that have been allocated during setup.
func TestTrustDB(t *testing.T, db TestableTrustDB) {
	testWrapper := func(test func(*testing.T, trustdb.ReadWrite)) func() {
		return func() {
			prepareCtx, cancelF := context.WithTimeout(context.Background(), Timeout)
			defer cancelF()
			db.Prepare(t, prepareCtx)
			test(t, db)
		}
	}
	Convey("TestTRC", testWrapper(testTRC))
	Convey("TestTRCGetAll", testWrapper(testTRCGetAll))
	Convey("TestIssCert", testWrapper(testIssCert))
	Convey("TestGetAllIssCerts", testWrapper(testGetAllIssCerts))
	Convey("TestChain", testWrapper(testChain))
	Convey("TestChainGetAll", testWrapper(testChainGetAll))
	Convey("TestCustKey", testWrapper(testCustKey))
	Convey("TestGetAllCustKeys", testWrapper(testGetAllCustKeys))
	// Now test everything with a transaction as well.
	txTestWrapper := func(test func(*testing.T, trustdb.ReadWrite)) func() {
		return func() {
			ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
			defer cancelF()
			db.Prepare(t, ctx)
			tx, err := db.BeginTransaction(ctx, nil)
			xtest.FailOnErr(t, err)
			test(t, tx)
			err = tx.Commit()
			xtest.FailOnErr(t, err)
		}
	}
	trustDbTestWrapper := func(test func(*testing.T, trustdb.TrustDB)) func() {
		return func() {
			prepareCtx, cancelF := context.WithTimeout(context.Background(), Timeout)
			defer cancelF()
			db.Prepare(t, prepareCtx)
			test(t, db)
		}
	}
	Convey("WithTransaction", func() {
		Convey("TestTRC", txTestWrapper(testTRC))
		Convey("TestTRCGetAll", txTestWrapper(testTRCGetAll))
		Convey("TestIssCert", txTestWrapper(testIssCert))
		Convey("TestGetAllIssCerts", txTestWrapper(testGetAllIssCerts))
		Convey("TestChain", txTestWrapper(testChain))
		Convey("TestChainGetAll", txTestWrapper(testChainGetAll))
		Convey("TestCustKey", txTestWrapper(testCustKey))
		Convey("TestGetAllCustKeys", txTestWrapper(testGetAllCustKeys))
		Convey("TransactionRollback", trustDbTestWrapper(testRollback))
	})
}

func testTRC(t *testing.T, db trustdb.ReadWrite) {
	Convey("Initialize DB and load TRC", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
		defer cancelF()

		trcobj, err := trc.TRCFromFile(filePath("ISD1-V1.trc"), false)
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

func testTRCGetAll(t *testing.T, db trustdb.ReadWrite) {
	Convey("Test get all TRCs", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		Convey("GetAllTRCs on empty DB does not fail and returns nil", func() {
			trcChan, err := db.GetAllTRCs(ctx)
			SoMsg("err", err, ShouldBeNil)
			r, more := <-trcChan
			SoMsg("more", more, ShouldBeFalse)
			SoMsg("r", r, ShouldResemble, trustdb.TrcOrErr{})
		})
		Convey("GetAllTRCs on DB with 1 entry does not fail and returns entry", func() {
			trcObj := insertTRCFromFile(t, ctx, "ISD1-V1.trc", db)
			trcChan, err := db.GetAllTRCs(ctx)
			SoMsg("err", err, ShouldBeNil)
			var trcs []*trc.TRC
			for r := range trcChan {
				SoMsg("r.Err", r.Err, ShouldBeNil)
				SoMsg("r.TRC", r.TRC, ShouldNotBeNil)
				trcs = append(trcs, r.TRC)
			}
			SoMsg("trcs", trcs, ShouldResemble, []*trc.TRC{trcObj})
		})
		Convey("GetAllTRCs on DB with 2 entries does not fail and returns entries", func() {
			trcObj := insertTRCFromFile(t, ctx, "ISD1-V1.trc", db)
			trcObj2 := insertTRCFromFile(t, ctx, "ISD2-V1.trc", db)
			trcChan, err := db.GetAllTRCs(ctx)
			SoMsg("err", err, ShouldBeNil)
			var trcs []*trc.TRC
			for r := range trcChan {
				SoMsg("r.Err", r.Err, ShouldBeNil)
				SoMsg("r.TRC", r.TRC, ShouldNotBeNil)
				trcs = append(trcs, r.TRC)
			}
			SoMsg("trcs", trcs, ShouldResemble, []*trc.TRC{trcObj, trcObj2})
		})
	})
}

func insertTRCFromFile(t *testing.T, ctx context.Context,
	fName string, db trustdb.ReadWrite) *trc.TRC {

	trcobj, err := trc.TRCFromFile(filePath(fName), false)
	xtest.FailOnErr(t, err)
	_, err = db.InsertTRC(ctx, trcobj)
	xtest.FailOnErr(t, err)
	return trcobj
}

func testIssCert(t *testing.T, db trustdb.ReadWrite) {
	Convey("Initialize DB and load issuer Cert", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
		defer cancelF()

		chain, err := cert.ChainFromFile(filePath("ISD1-ASff00_0_311-V1.crt"), false)
		xtest.FailOnErr(t, err, "Unable to load certificate chain")

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

func testGetAllIssCerts(t *testing.T, db trustdb.ReadWrite) {
	Convey("Test get all issuer certs", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		Convey("GetAllIssCerts on empty DB does not fail and returns nil", func() {
			crtChan, err := db.GetAllIssCerts(ctx)
			SoMsg("err", err, ShouldBeNil)
			r, more := <-crtChan
			SoMsg("channel", more, ShouldBeFalse)
			SoMsg("r", r, ShouldResemble, trustdb.CertOrErr{})
		})
		Convey("GetAllIssCerts on DB with 1 entry does not fail and returns entry", func() {
			crt := insertIssCertFromFile(t, ctx, "ISD1-ASff00_0_311-V1.crt", db)
			crtChan, err := db.GetAllIssCerts(ctx)
			SoMsg("err", err, ShouldBeNil)
			var crts []*cert.Certificate
			for r := range crtChan {
				SoMsg("r.Err", r.Err, ShouldBeNil)
				SoMsg("r.Cert", r.Cert, ShouldNotBeNil)
				crts = append(crts, r.Cert)
			}
			SoMsg("Certs", crts, ShouldResemble, []*cert.Certificate{crt})
		})
		Convey("GetAllIssCerts on DB with 2 entries does not fail and returns entries", func() {
			crt := insertIssCertFromFile(t, ctx, "ISD1-ASff00_0_311-V1.crt", db)
			crt2 := insertIssCertFromFile(t, ctx, "ISD2-ASff00_0_212-V1.crt", db)
			crtChan, err := db.GetAllIssCerts(ctx)
			SoMsg("err", err, ShouldBeNil)
			var crts []*cert.Certificate
			for r := range crtChan {
				SoMsg("r.Err", r.Err, ShouldBeNil)
				SoMsg("r.Cert", r.Cert, ShouldNotBeNil)
				crts = append(crts, r.Cert)
			}
			SoMsg("Certs", crts, ShouldResemble, []*cert.Certificate{crt, crt2})
		})
	})
}

func testChain(t *testing.T, db trustdb.ReadWrite) {
	Convey("Initialize DB and load Chain", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
		defer cancelF()

		chain, err := cert.ChainFromFile(filePath("ISD1-ASff00_0_311-V1.crt"), false)
		xtest.FailOnErr(t, err)
		ia := addr.IA{I: 1, A: 0xff0000000311}
		Convey("Insert into database", func() {
			rows, err := db.InsertChain(ctx, chain)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldNotEqual, 0)
			rows, err = db.InsertChain(ctx, chain)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("rows", rows, ShouldEqual, 0)
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
		Convey("Given a DB with 2 chains, Getting a chain works fine", func() {
			chain := insertChainFromFile(t, ctx, "ISD1-ASff00_0_311-V1.crt", db)
			insertChainFromFile(t, ctx, "ISD2-ASff00_0_212-V1.crt", db)
			newChain, err := db.GetChainMaxVersion(ctx, ia)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("chain", newChain, ShouldResemble, chain)
			newChain, err = db.GetChainVersion(ctx, ia, 1)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("chain", newChain, ShouldResemble, chain)
		})
	})
}

func testChainGetAll(t *testing.T, db trustdb.ReadWrite) {
	Convey("Test get all chains", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		Convey("GetAllChains on empty DB does not fail and return nil", func() {
			chainChan, err := db.GetAllChains(ctx)
			SoMsg("err", err, ShouldBeNil)
			r, more := <-chainChan
			SoMsg("channel", more, ShouldBeFalse)
			SoMsg("r", r, ShouldResemble, trustdb.ChainOrErr{})
		})
		Convey("GetAllChains on DB with 1 entry does not fail and returns entry", func() {
			chain := insertChainFromFile(t, ctx, "ISD1-ASff00_0_311-V1.crt", db)
			chainChan, err := db.GetAllChains(ctx)
			SoMsg("err", err, ShouldBeNil)
			var chains []*cert.Chain
			for r := range chainChan {
				SoMsg("r.Err", r.Err, ShouldBeNil)
				SoMsg("r.Chain", r.Chain, ShouldNotBeNil)
				chains = append(chains, r.Chain)
			}
			SoMsg("chains", chains, ShouldResemble, []*cert.Chain{chain})
		})
		Convey("GetAllChains on DB with 2 entries does not fail and returns entries", func() {
			chain := insertChainFromFile(t, ctx, "ISD1-ASff00_0_311-V1.crt", db)
			chain2 := insertChainFromFile(t, ctx, "ISD2-ASff00_0_212-V1.crt", db)
			chainChan, err := db.GetAllChains(ctx)
			SoMsg("err", err, ShouldBeNil)
			var chains []*cert.Chain
			for r := range chainChan {
				SoMsg("r.Err", r.Err, ShouldBeNil)
				SoMsg("r.Chain", r.Chain, ShouldNotBeNil)
				chains = append(chains, r.Chain)
			}
			SoMsg("chains", chains, ShouldResemble, []*cert.Chain{chain, chain2})
		})
	})
}

func testCustKey(t *testing.T, db trustdb.ReadWrite) {
	Convey("Cust Key tests on an emptry trust db", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), Timeout)
		defer cancelF()

		ia1_110 := xtest.MustParseIA("1-ff00:0:110")
		key_110_1 := common.RawBytes("dddddddd")
		key_110_2 := common.RawBytes("ddddddaa")

		Convey("GetCustKey should return nil and no error", func() {
			key, err := db.GetCustKey(ctx, ia1_110)
			SoMsg("No error expected", err, ShouldBeNil)
			SoMsg("Empty result expected", key, ShouldBeNil)
		})
		Convey("Insertion should work without error", func() {
			var ver uint64 = 1
			key := &trustdb.CustKey{IA: ia1_110, Version: ver, Key: key_110_1}
			err := db.InsertCustKey(ctx, key, 0)
			SoMsg("No error expected", err, ShouldBeNil)
			Convey("Inserted entry should be returned", func() {
				actKey, err := db.GetCustKey(ctx, ia1_110)
				SoMsg("No error expected", err, ShouldBeNil)
				SoMsg("Inserted key expected", actKey, ShouldResemble, key)
			})
			Convey("Inserting a newer version should work", func() {
				var newVer uint64 = 2
				key2 := &trustdb.CustKey{IA: ia1_110, Version: newVer, Key: key_110_2}
				err := db.InsertCustKey(ctx, key2, ver)
				SoMsg("No error expected", err, ShouldBeNil)
				Convey("New version should be returned", func() {
					actKey, err := db.GetCustKey(ctx, ia1_110)
					SoMsg("No error expected", err, ShouldBeNil)
					SoMsg("Inserted key expected", actKey, ShouldResemble, key2)
				})
			})
			Convey("Inserting the same version again should error", func() {
				key.Key = key_110_2
				err := db.InsertCustKey(ctx, key, ver)
				SoMsg("Error expected", err, ShouldNotBeNil)
			})
			Convey("Inserting with 0 version should fail if there is an entry", func() {
				err := db.InsertCustKey(ctx, key, 0)
				SoMsg("Error expected", err, ShouldNotBeNil)
			})
			Convey("Updating with outdated old version should fail", func() {
				var newVer uint64 = 2
				key2 := &trustdb.CustKey{IA: ia1_110, Version: newVer, Key: key_110_2}
				err := db.InsertCustKey(ctx, key2, ver)
				SoMsg("No error expected", err, ShouldBeNil)
				err = db.InsertCustKey(ctx, key2, ver)
				SoMsg("Error expected", err, ShouldNotBeNil)
			})
		})
	})
}

func testGetAllCustKeys(t *testing.T, db trustdb.ReadWrite) {
	key110 := &trustdb.CustKey{
		IA:      xtest.MustParseIA("1-ff00:0:110"),
		Key:     common.RawBytes("dddddddd"),
		Version: 1,
	}
	key111 := &trustdb.CustKey{
		IA:      xtest.MustParseIA("1-ff00:0:111"),
		Key:     common.RawBytes("ddddddaa"),
		Version: 1,
	}

	Convey("Test get all customer keys", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		Convey("GetAllCustKeys on empty DB does not fail and returns nil", func() {
			custKeyChan, err := db.GetAllCustKeys(ctx)
			SoMsg("err", err, ShouldBeNil)
			r, more := <-custKeyChan
			SoMsg("channel", more, ShouldBeFalse)
			SoMsg("r", r, ShouldResemble, trustdb.CustKeyOrErr{})
		})
		Convey("GetAllCustKeys with 1 entry does not fail and returns entry", func() {
			err := db.InsertCustKey(ctx, key110, 0)
			xtest.FailOnErr(t, err)
			custKeyChan, err := db.GetAllCustKeys(ctx)
			SoMsg("err", err, ShouldBeNil)
			var keys []*trustdb.CustKey
			for r := range custKeyChan {
				SoMsg("r.Err", r.Err, ShouldBeNil)
				SoMsg("r.CustKey", r.CustKey, ShouldNotBeNil)
				keys = append(keys, r.CustKey)
			}
			SoMsg("keys", keys, ShouldResemble, []*trustdb.CustKey{key110})
		})
		Convey("GetAllCustKeys with 2 entries does not fail and returns entries", func() {
			err := db.InsertCustKey(ctx, key110, 0)
			xtest.FailOnErr(t, err)
			err = db.InsertCustKey(ctx, key111, 0)
			xtest.FailOnErr(t, err)
			custKeyChan, err := db.GetAllCustKeys(ctx)
			SoMsg("err", err, ShouldBeNil)
			var keys []*trustdb.CustKey
			for r := range custKeyChan {
				SoMsg("r.Err", r.Err, ShouldBeNil)
				SoMsg("r.CustKey", r.CustKey, ShouldNotBeNil)
				keys = append(keys, r.CustKey)
			}
			SoMsg("keys", keys, ShouldResemble, []*trustdb.CustKey{key110, key111})
		})
	})
}

func testRollback(t *testing.T, db trustdb.TrustDB) {
	Convey("Test transaction rollback", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		tx, err := db.BeginTransaction(ctx, nil)
		SoMsg("Transaction begin should not fail", err, ShouldBeNil)
		trcobj, err := trc.TRCFromFile(filePath("ISD1-V1.trc"), false)
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
	fName string, db trustdb.ReadWrite) *cert.Chain {

	chain, err := cert.ChainFromFile(filePath(fName), false)
	xtest.FailOnErr(t, err)
	_, err = db.InsertChain(ctx, chain)
	xtest.FailOnErr(t, err)
	return chain
}

func insertIssCertFromFile(t *testing.T, ctx context.Context,
	fName string, db trustdb.ReadWrite) *cert.Certificate {

	chain, err := cert.ChainFromFile(filePath(fName), false)
	xtest.FailOnErr(t, err, "Unable to load certificate chain")
	_, err = db.InsertIssCert(ctx, chain.Issuer)
	xtest.FailOnErr(t, err)
	return chain.Issuer
}

func filePath(fName string) string {
	return fmt.Sprintf("%s/%s", strings.TrimSuffix(TestDataRelPath, "/"), fName)
}
