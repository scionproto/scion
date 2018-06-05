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

package trust

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet/rpt"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/loader"
	"github.com/scionproto/scion/go/lib/xtest/p2p"
)

var (
	isds = []addr.ISD{1, 2, 3, 4, 5}
	ias  = []addr.IA{
		xtest.MustParseIA("1-ff00:0:1"), xtest.MustParseIA("1-ff00:0:2"),
		xtest.MustParseIA("1-ff00:0:3"), xtest.MustParseIA("2-ff00:0:4"),
		xtest.MustParseIA("2-ff00:0:5"), xtest.MustParseIA("2-ff00:0:6"),
		xtest.MustParseIA("3-ff00:0:7"), xtest.MustParseIA("3-ff00:0:8"),
		xtest.MustParseIA("3-ff00:0:9"), xtest.MustParseIA("4-ff00:0:a"),
		xtest.MustParseIA("4-ff00:0:b"), xtest.MustParseIA("4-ff00:0:c"),
		xtest.MustParseIA("5-ff00:0:d"), xtest.MustParseIA("5-ff00:0:e"),
		xtest.MustParseIA("5-ff00:0:f"),
	}
	tmpDir string
)

func TestMain(m *testing.M) {
	var cleanF func()
	tmpDir, cleanF = xtest.MustTempDir("", "test-trust")
	defer cleanF()
	if err := regenerateCrypto(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}

func regenerateCrypto() error {
	b := &loader.Binary{
		Target: "github.com/scionproto/scion/go/tools/scion-pki",
		Dir:    tmpDir,
	}
	if err := b.Build(); err != nil {
		panic(err)
	}

	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	confDir := filepath.Join(wd, "/testdata")
	cmd := b.Cmd("keys", "gen", "-d", confDir, "-o", tmpDir, "*-*")
	if msg, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("scion-pki: %s", msg)
	}

	cmd = b.Cmd("trc", "gen", "-d", confDir, "-o", tmpDir, "*")
	if msg, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("scion-pki: %s", msg)
	}

	cmd = b.Cmd("certs", "gen", "-d", confDir, "-o", tmpDir, "*-*")
	if msg, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("scion-pki: %s", msg)
	}
	return nil
}

func TestGetValidTRC(t *testing.T) {
	trcs, chains := loadCrypto(t, isds, ias)

	testCases := []struct {
		Name          string
		ISD           addr.ISD
		Trail         []addr.ISD
		ExpData       *trc.TRC
		ExpError      bool
		DBTRCInChecks []*trc.TRC // Check that these objects were saved to persistent storage
	}{
		{
			Name: "bad ISD=0",
			ISD:  0, Trail: []addr.ISD{0},
			ExpData: nil, ExpError: true,
		},
		{
			Name: "local ISD=1",
			ISD:  1, Trail: []addr.ISD{1},
			ExpData: trcs[1], ExpError: false,
		},
		{
			Name: "unknown ISD=2, nil trail",
			ISD:  2, Trail: nil,
			ExpData: nil, ExpError: true,
		},
		{
			Name: "unknown ISD=2, empty trail",
			ISD:  2, Trail: []addr.ISD{},
			ExpData: nil, ExpError: true,
		},
		{
			Name: "unknown ISD=5, bad trail",
			ISD:  5, Trail: []addr.ISD{1, 2, 3},
			ExpData: nil, ExpError: true,
		},
		{
			Name: "unknown ISD=2, 2-length trail, no trust root in trail",
			ISD:  2, Trail: []addr.ISD{2, 3},
			ExpData: nil, ExpError: true,
		},
		{
			Name: "unknown ISD=2, 2-length trail, trust root in trail",
			ISD:  2, Trail: []addr.ISD{2, 1},
			ExpData: trcs[2], ExpError: false,
		},
		{
			Name: "unknown ISD=2, 3-length trail, trust root mid-trail ",
			ISD:  2, Trail: []addr.ISD{2, 1, 3},
			ExpData: trcs[2], ExpError: false,
			DBTRCInChecks: []*trc.TRC{trcs[2]},
		},
		{
			Name: "unknown ISD=2, 3-length trail, trust root at end of trail",
			ISD:  2, Trail: []addr.ISD{2, 3, 1},
			ExpData: trcs[2], ExpError: false,
			DBTRCInChecks: []*trc.TRC{trcs[2], trcs[3]},
		},
		{
			Name: "bogus ISD=42, 2-length trail",
			ISD:  42, Trail: []addr.ISD{42, 1},
			ExpData: nil, ExpError: true,
		},
	}

	Convey("Get valid TRCs", t, func() {
		msger := &messenger.MockMessenger{
			TRCs:   trcs,
			Chains: chains,
		}
		store, cleanF := initStore(t, xtest.MustParseIA("1-ff00:0:1"), msger)
		defer cleanF()

		insertTRC(t, store, trcs[1])

		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
				defer cancelF()

				trcObj, err := store.GetValidTRC(ctx, tc.ISD, tc.Trail...)
				xtest.SoMsgError("err", err, tc.ExpError)
				SoMsg("trc", trcObj, ShouldResemble, tc.ExpData)

				// Post-check DB state to verify insertion
				for _, trcObj := range tc.DBTRCInChecks {
					get, err := store.trustdb.GetTRCVersion(trcObj.ISD, trcObj.Version)
					SoMsg("db err", err, ShouldBeNil)
					SoMsg("db trc", get, ShouldResemble, trcObj)
				}
			})
		}
	})
}

func TestGetTRC(t *testing.T) {
	trcs, chains := loadCrypto(t, isds, ias)

	testCases := []struct {
		Name     string
		ISD      addr.ISD
		Version  uint64
		ExpData  *trc.TRC
		ExpError bool

		DBTRCNotInChecks []*trc.TRC // Explicitly check that these objects where not saved to DB
	}{
		{
			Name: "bad ISD=0",
			ISD:  0, Version: 1,
			ExpData: nil, ExpError: true,
		},
		{
			Name: "local ISD=1, version 1",
			ISD:  1, Version: 1,
			ExpData: trcs[1], ExpError: false,
		},
		{
			Name: "local ISD=1, max version",
			ISD:  1, Version: 0,
			ExpData: trcs[1], ExpError: false,
		},
		{
			Name: "local ISD=1, unknown version",
			ISD:  1, Version: 4,
			ExpData: nil, ExpError: true,
		},
		{
			Name: "unknown ISD=2, version 1",
			ISD:  2, Version: 1,
			ExpData: trcs[2], ExpError: false,
			DBTRCNotInChecks: []*trc.TRC{trcs[2]},
		},
		{
			Name: "unknown ISD=2, max version",
			ISD:  2, Version: 0,
			ExpData: trcs[2], ExpError: false,
		},
		{
			Name: "remote ISD=3, version 1",
			ISD:  3, Version: 1,
			ExpData: trcs[3], ExpError: false,
		},
		{
			Name: "remote ISD=3, max version",
			ISD:  3, Version: 0,
			ExpData: trcs[3], ExpError: false,
		},
		{
			Name: "remote ISD=3, unknown version",
			ISD:  3, Version: 4,
			ExpData: nil, ExpError: true,
		},
		{
			Name: "bogus ISD=42",
			ISD:  42, Version: 1,
			ExpData: nil, ExpError: true,
		},
	}

	Convey("Get unverified TRCs", t, func() {
		msger := &messenger.MockMessenger{
			TRCs:   trcs,
			Chains: chains,
		}
		store, cleanF := initStore(t, xtest.MustParseIA("1-ff00:0:1"), msger)
		defer cleanF()

		insertTRC(t, store, trcs[1])
		insertTRC(t, store, trcs[3])

		for _, tc := range testCases[4:5] {
			Convey(tc.Name, func() {
				ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
				defer cancelF()

				trcObj, err := store.GetTRC(ctx, tc.ISD, tc.Version)
				xtest.SoMsgError("err", err, tc.ExpError)
				SoMsg("trc", trcObj, ShouldResemble, tc.ExpData)

				// Post-check DB state to verify that unverified objects were not inserted
				for _, trcObj := range tc.DBTRCNotInChecks {
					get, err := store.trustdb.GetTRCVersion(trcObj.ISD, trcObj.Version)
					SoMsg("db err", err, ShouldBeNil)
					SoMsg("db trc", get, ShouldBeNil)
				}
			})
		}
	})

}

func TestGetValidChain(t *testing.T) {
	trcs, chains := loadCrypto(t, isds, ias)

	testCases := []struct {
		Name            string
		IA              addr.IA
		Trail           []addr.ISD
		ExpData         *cert.Chain
		ExpError        bool
		DBChainInChecks []*cert.Chain // Check that these objects were saved to persistent storage
	}{
		{
			Name: "bad IA=0-1",
			IA:   xtest.MustParseIA("0-ff00:0:1"), Trail: []addr.ISD{0},
			ExpData: nil, ExpError: true,
		},
		{
			Name: "bad IA=1-0",
			IA:   addr.IA{I: 1, A: 0}, Trail: []addr.ISD{0},
			ExpData: nil, ExpError: true,
		},
		{
			Name: "local IA=1-1",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Trail: []addr.ISD{1},
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ExpError: false,
		},
		{
			Name: "remote IA=2-4",
			IA:   xtest.MustParseIA("2-ff00:0:4"), Trail: []addr.ISD{2, 1},
			ExpData: chains[xtest.MustParseIA("2-ff00:0:4")], ExpError: false,
			DBChainInChecks: []*cert.Chain{chains[xtest.MustParseIA("2-ff00:0:4")]},
		},
	}

	Convey("Get Chains", t, func() {
		msger := &messenger.MockMessenger{
			TRCs:   trcs,
			Chains: chains,
		}
		store, cleanF := initStore(t, xtest.MustParseIA("1-ff00:0:1"), msger)
		defer cleanF()

		insertTRC(t, store, trcs[1])

		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
				defer cancelF()

				chain, err := store.GetValidChain(ctx, tc.IA, tc.Trail...)
				xtest.SoMsgError("err", err, tc.ExpError)
				SoMsg("trc", chain, ShouldResemble, tc.ExpData)

				// Post-check DB state to verify insertion
				for _, chain := range tc.DBChainInChecks {
					get, err := store.trustdb.GetChainVersion(chain.Leaf.Subject,
						chain.Leaf.Version)
					SoMsg("db err", err, ShouldBeNil)
					SoMsg("db chain", get, ShouldResemble, chain)
				}
			})
		}
	})
}

func TestGetChain(t *testing.T) {
	trcs, chains := loadCrypto(t, isds, ias)

	testCases := []struct {
		Name               string
		IA                 addr.IA
		Version            uint64
		Trail              []addr.ISD
		ExpData            *cert.Chain
		ExpError           bool
		DBChainNotInChecks []*cert.Chain // Check that these objects were not saved to DB
	}{
		{
			Name: "bad IA=0-1",
			IA:   xtest.MustParseIA("0-ff00:0:1"), Version: 0,
			ExpData: nil, ExpError: true,
		},
		{
			Name: "bad IA=1-0",
			IA:   addr.IA{I: 1, A: 0}, Version: 0,
			ExpData: nil, ExpError: true,
		},
		{
			Name: "local IA=1-1, version 1",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: 1,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ExpError: false,
		},
		{
			Name: "local IA=1-1, max version",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: 0,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ExpError: false,
		},
		{
			Name: "local IA=1-1, unknown version 4",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: 4,
			ExpData: nil, ExpError: true,
		},
		{
			Name: "unknown IA=2-4", IA: xtest.MustParseIA("2-ff00:0:4"),
			ExpData: chains[xtest.MustParseIA("2-ff00:0:4")], ExpError: false,
			DBChainNotInChecks: []*cert.Chain{chains[xtest.MustParseIA("2-ff00:0:4")]},
		},
		{
			Name: "remote IA=3-9, version 1",
			IA:   xtest.MustParseIA("3-ff00:0:9"), Version: 1,
			ExpData: chains[xtest.MustParseIA("3-ff00:0:9")], ExpError: false,
		},
		{
			Name: "remote IA=3-9, max version",
			IA:   xtest.MustParseIA("3-ff00:0:9"), Version: 0,
			ExpData: chains[xtest.MustParseIA("3-ff00:0:9")], ExpError: false,
		},
		{
			Name: "remote IA=3-9, unknown version 4",
			IA:   xtest.MustParseIA("3-ff00:0:9"), Version: 4,
			ExpData: nil, ExpError: true,
		},
		{
			Name: "bogus IA=42-9",
			IA:   xtest.MustParseIA("42-ff00:0:9"), Version: 1,
			ExpData: nil, ExpError: true,
		},
	}

	Convey("Get unverified chains", t, func() {
		msger := &messenger.MockMessenger{
			TRCs:   trcs,
			Chains: chains,
		}
		store, cleanF := initStore(t, xtest.MustParseIA("1-ff00:0:1"), msger)
		defer cleanF()

		insertTRC(t, store, trcs[1])
		insertChain(t, store, chains[xtest.MustParseIA("1-ff00:0:1")])
		insertTRC(t, store, trcs[3])
		insertChain(t, store, chains[xtest.MustParseIA("3-ff00:0:9")])

		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
				defer cancelF()

				chain, err := store.GetChain(ctx, tc.IA, tc.Version)
				xtest.SoMsgError("err", err, tc.ExpError)
				SoMsg("trc", chain, ShouldResemble, tc.ExpData)

				// Post-check DB state to verify that unverified objects were not inserted
				for _, chain := range tc.DBChainNotInChecks {
					get, err := store.trustdb.GetChainVersion(chain.Leaf.Subject,
						chain.Leaf.Version)
					SoMsg("db err", err, ShouldBeNil)
					SoMsg("db chain", get, ShouldBeNil)
				}
			})
		}
	})
}

func TestTRCReqHandler(t *testing.T) {
	trcs, chains := loadCrypto(t, isds, ias)

	testCases := []struct {
		Name             string
		ISD              addr.ISD
		Version          uint64
		ExpData          *trc.TRC
		ExpError         bool
		RecursionEnabled bool // Tell the server to recurse on unknown objects
		CacheOnly        bool // Tell the client to override server's recursion settings
	}{
		{
			Name: "ask for known isd=1, version=max, cache-only, recursive",
			ISD:  1, Version: 0,
			ExpData: trcs[1], ExpError: false,
			RecursionEnabled: true, CacheOnly: true,
		},
		{
			Name: "ask for known isd=1, version=max, cache-only, non-recursive",
			ISD:  1, Version: 0,
			ExpData: trcs[1], ExpError: false,
			RecursionEnabled: false, CacheOnly: true,
		},
		{
			Name: "ask for known isd=1, version=max, cache-only=false, recursive",
			ISD:  1, Version: 0,
			ExpData: trcs[1], ExpError: false,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for known isd=1, version=max, cache-only=false, non-recursive",
			ISD:  1, Version: 0,
			ExpData: trcs[1], ExpError: false,
			RecursionEnabled: false, CacheOnly: false,
		},
		{
			Name: "ask for known isd=1, version=1, cache-only=false, recursive",
			ISD:  1, Version: 1,
			ExpData: trcs[1], ExpError: false,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for known isd=1, bogus ver=4, cache-only=false, recursive",
			ISD:  1, Version: 4,
			ExpData: nil, ExpError: true,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for unknown isd=2, version=max, cache-only, recursive",
			ISD:  2, Version: 0,
			ExpData: nil, ExpError: true,
			RecursionEnabled: true, CacheOnly: true,
		},
		{
			Name: "ask for unknown isd=2, version=max, cache-only, non-recursive",
			ISD:  2, Version: 0,
			ExpData: nil, ExpError: true,
			RecursionEnabled: false, CacheOnly: true,
		},
		{
			Name: "ask for unknown isd=2, version=max, cache-only=false, recursive",
			ISD:  2, Version: 0,
			ExpData: trcs[2], ExpError: false,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for known isd=2, version=max, cache-only=false, non-recursive",
			ISD:  2, Version: 0,
			ExpData: nil, ExpError: true,
			RecursionEnabled: false, CacheOnly: false,
		},
		{
			Name: "ask for bogus isd=42, version=max, cache-only=false, recursive",
			ISD:  42, Version: 0,
			ExpData: nil, ExpError: true,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for bogus isd=42, version=max, cache-only=true, non-recursive",
			ISD:  42, Version: 0,
			ExpData: nil, ExpError: true,
			RecursionEnabled: false, CacheOnly: true,
		},
	}

	// The trust store under test plays the role of the server. It runs paired
	// with a full Messenger implementation that runs ListenAndServe, thus
	// redirecting TRC requests to the trust store. The trust store uses a
	// separate MockMessenger to download objects (when recursing). In an
	// actual server, the roles of both Messengers are played by a single
	// object.
	//
	// ClientMsger <-> ServerMsger=TrustStore <-> MockMsger
	//     --test_requests-->         <--crypto_objects--
	//
	// ClientMsger runs without a trust store.
	Convey("Test TRCReq Handler", t, func() {
		msger := &messenger.MockMessenger{
			TRCs:   trcs,
			Chains: chains,
		}
		store, cleanF := initStore(t, xtest.MustParseIA("1-ff00:0:1"), msger)
		defer cleanF()

		insertTRC(t, store, trcs[1])

		c2s, s2c := p2p.New()
		// each test initiates a request from the client messenger
		clientMessenger := setupMessenger(c2s, nil, "client")
		// the server messenger runs ListenAndServe, backed by the trust store
		serverMessenger := setupMessenger(s2c, store, "server")

		for _, tc := range testCases {
			Convey(tc.Name, func() {
				handler := store.NewTRCReqHandler(tc.RecursionEnabled)
				serverMessenger.AddHandler(messenger.TRCRequest, handler)
				go serverMessenger.ListenAndServe()
				defer serverMessenger.CloseServer()

				ctx, cancelF := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancelF()

				msg := &cert_mgmt.TRCReq{
					ISD:       tc.ISD,
					Version:   tc.Version,
					CacheOnly: tc.CacheOnly,
				}
				reply, err := clientMessenger.GetTRC(ctx, msg, nil, 73)
				xtest.SoMsgError("err", err, tc.ExpError)
				if reply != nil {
					trcObj, err := reply.TRC()
					SoMsg("trc err", err, ShouldBeNil)
					SoMsg("trc", trcObj, ShouldResemble, tc.ExpData)
				}
			})
		}
	})
}

func TestChainReqHandler(t *testing.T) {
	trcs, chains := loadCrypto(t, isds, ias)

	testCases := []struct {
		Name             string
		IA               addr.IA
		Version          uint64
		ExpData          *cert.Chain
		ExpError         bool
		RecursionEnabled bool // Tell the server to recurse on unknown objects
		CacheOnly        bool // Tell the client to override server's recursion settings
	}{
		{
			Name: "ask for known chain=1-1, version=max, cache-only, recursive",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: 0,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ExpError: false,
			RecursionEnabled: true, CacheOnly: true,
		},
		{
			Name: "ask for known chain=1-1, version=max, cache-only, non-recursive",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: 0,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ExpError: false,
			RecursionEnabled: false, CacheOnly: true,
		},
		{
			Name: "ask for known chain=1-1, version=max, cache-only=false, recursive",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: 0,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ExpError: false,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for known chain=1-1, version=max, cache-only=false, non-recursive",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: 0,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ExpError: false,
			RecursionEnabled: false, CacheOnly: false,
		},
		{
			Name: "ask for known chain=1-1, version=1, cache-only=false, recursive",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: 1,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ExpError: false,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for known chain=1-1, version=4, cache-only=false, recursive",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: 4,
			ExpData: nil, ExpError: true,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for unknown chain=1-2, version=max, cache-only, recursive",
			IA:   xtest.MustParseIA("1-ff00:0:2"), Version: 0,
			ExpData: nil, ExpError: true,
			RecursionEnabled: true, CacheOnly: true,
		},
		{
			Name: "ask for unknown chain=1-2, version=max, cache-only, non-recursive",
			IA:   xtest.MustParseIA("1-ff00:0:2"), Version: 0,
			ExpData: nil, ExpError: true,
			RecursionEnabled: false, CacheOnly: true,
		},
		{
			Name: "ask for unknown chain=1-2, version=max, cache-only=false, recursive",
			IA:   xtest.MustParseIA("1-ff00:0:2"), Version: 0,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:2")], ExpError: false,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for unknown chain=1-2, version=max, cache-only=false, non-recursive",
			IA:   xtest.MustParseIA("1-ff00:0:2"), Version: 0,
			ExpData: nil, ExpError: true,
			RecursionEnabled: false, CacheOnly: false,
		},
	}

	// See TestTRCReqHandler for info about the testing setup.
	Convey("Test ChainReq Handler", t, func() {
		msger := &messenger.MockMessenger{
			TRCs:   trcs,
			Chains: chains,
		}
		store, cleanF := initStore(t, xtest.MustParseIA("1-ff00:0:1"), msger)
		defer cleanF()

		insertTRC(t, store, trcs[1])
		insertChain(t, store, chains[xtest.MustParseIA("1-ff00:0:1")])

		c2s, s2c := p2p.New()
		// each test initiates a request from the client messenger
		clientMessenger := setupMessenger(c2s, nil, "client")
		// the server messenger runs ListenAndServe, backed by the trust store
		serverMessenger := setupMessenger(s2c, store, "server")

		for _, tc := range testCases {
			Convey(tc.Name, func() {
				handler := store.NewChainReqHandler(tc.RecursionEnabled)
				serverMessenger.AddHandler(messenger.ChainRequest, handler)
				go serverMessenger.ListenAndServe()
				defer serverMessenger.CloseServer()

				ctx, cancelF := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancelF()

				msg := &cert_mgmt.ChainReq{
					RawIA:     tc.IA.IAInt(),
					Version:   tc.Version,
					CacheOnly: tc.CacheOnly,
				}
				reply, err := clientMessenger.GetCertChain(ctx, msg, nil, 73)
				xtest.SoMsgError("err", err, tc.ExpError)
				if reply != nil {
					chain, err := reply.Chain()
					SoMsg("chain err", err, ShouldBeNil)
					SoMsg("chain", chain, ShouldResemble, tc.ExpData)
				}
			})
		}
	})
}

func setupMessenger(conn net.PacketConn, store *Store, name string) infra.Messenger {
	transport := rpt.New(conn, log.New("name", name))
	dispatcher := disp.New(transport, messenger.DefaultAdapter, log.New("name", name))
	return messenger.New(dispatcher, store, log.Root().New("name", name))
}

func loadCrypto(t *testing.T, isds []addr.ISD,
	ias []addr.IA) (map[addr.ISD]*trc.TRC, map[addr.IA]*cert.Chain) {

	t.Helper()
	var err error

	trcMap := make(map[addr.ISD]*trc.TRC)
	for _, isd := range isds {
		trcMap[isd], err = trc.TRCFromFile(getTRCFileName(isd, 1), false)
		if err != nil {
			t.Fatal(err)
		}
	}

	chainMap := make(map[addr.IA]*cert.Chain)
	for _, ia := range ias {
		chainMap[ia], err = cert.ChainFromFile(getChainFileName(ia, 1), false)
		if err != nil {
			t.Fatal(err)
		}
	}
	return trcMap, chainMap
}

func getTRCFileName(isd addr.ISD, version uint64) string {
	return fmt.Sprintf("%s/ISD%d/trcs/ISD%d-V%d.trc", tmpDir, isd, isd, version)
}

func getChainFileName(ia addr.IA, version uint64) string {
	return fmt.Sprintf("%s/ISD%d/AS%s/certs/ISD%d-AS%s-V%d.crt",
		tmpDir, ia.I, ia.A.FileFmt(), ia.I, ia.A.FileFmt(), version)
}

func initStore(t *testing.T, ia addr.IA, msger infra.Messenger) (*Store, func()) {
	t.Helper()

	dbFile := xtest.MustTempFileName("", "truststore-test")
	db, err := trustdb.New(dbFile)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(db, ia, 0, log.Root())
	if err != nil {
		t.Fatal(err)
	}

	// Enable fake network access for trust database
	store.SetMessenger(msger)
	return store, func() {
		db.Close()
		os.Remove(dbFile)
	}
}

func insertTRC(t *testing.T, store *Store, trcObj *trc.TRC) {
	t.Helper()

	_, err := store.trustdb.InsertTRC(trcObj)
	if err != nil {
		t.Fatal(err)
	}
}

func insertChain(t *testing.T, store *Store, chain *cert.Chain) {
	t.Helper()

	_, err := store.trustdb.InsertChain(chain)
	if err != nil {
		t.Fatal(err)
	}
}
