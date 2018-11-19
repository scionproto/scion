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

package trust

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb/trustdbsqlite"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/snet/rpt"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/topology/topotestutil"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/loader"
	"github.com/scionproto/scion/go/lib/xtest/p2p"
	"github.com/scionproto/scion/go/proto"
)

const (
	testCtxTimeout = 200 * time.Millisecond
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

func newMessengerMock(ctrl *gomock.Controller,
	trcs map[addr.ISD]*trc.TRC, chains map[addr.IA]*cert.Chain) infra.Messenger {

	msger := mock_infra.NewMockMessenger(ctrl)
	msger.EXPECT().GetTRC(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, msg *cert_mgmt.TRCReq,
			a net.Addr, id uint64) (*cert_mgmt.TRC, error) {

			trcObj, ok := trcs[msg.ISD]
			if !ok {
				return nil, common.NewBasicError("TRC not found", nil)
			}

			compressedTRC, err := trcObj.Compress()
			if err != nil {
				return nil, common.NewBasicError("Unable to compress TRC", nil)
			}
			return &cert_mgmt.TRC{RawTRC: compressedTRC}, nil
		},
	).AnyTimes()
	msger.EXPECT().GetCertChain(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, msg *cert_mgmt.ChainReq,
			a net.Addr, id uint64) (*cert_mgmt.Chain, error) {

			chain, ok := chains[msg.IA()]
			if !ok {
				return nil, common.NewBasicError("Chain not found", nil)
			}

			compressedChain, err := chain.Compress()
			if err != nil {
				return nil, common.NewBasicError("Unable to compress Chain", nil)
			}
			return &cert_mgmt.Chain{RawChain: compressedChain}, nil
		},
	).AnyTimes()
	return msger
}

func TestGetValidTRC(t *testing.T) {
	trcs, chains := loadCrypto(t, isds, ias)

	testCases := []struct {
		Name          string
		ISD           addr.ISD
		ExpData       *trc.TRC
		ExpError      bool
		DBTRCInChecks []*trc.TRC // Check that these objects were saved to persistent storage
	}{
		{
			Name:     "bad ISD=0",
			ISD:      0,
			ExpData:  nil,
			ExpError: true,
		},
		{
			Name:          "local ISD=1",
			ISD:           1,
			ExpData:       trcs[1],
			ExpError:      false,
			DBTRCInChecks: []*trc.TRC{trcs[1]},
		},
		{
			Name:     "unknown ISD=6",
			ISD:      6,
			ExpData:  nil,
			ExpError: true,
		},
	}

	Convey("Get valid TRCs", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		msger := newMessengerMock(ctrl, trcs, chains)
		store, cleanF := initStore(t, ctrl, xtest.MustParseIA("1-ff00:0:1"), msger)
		defer cleanF()

		insertTRC(t, store, trcs[1])

		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
				defer cancelF()

				trcObj, err := store.GetValidTRC(ctx, tc.ISD, nil)
				xtest.SoMsgError("err", err, tc.ExpError)
				SoMsg("trc", trcObj, ShouldResemble, tc.ExpData)

				// Post-check DB state to verify insertion
				for _, trcObj := range tc.DBTRCInChecks {
					get, err := store.trustdb.GetTRCVersion(ctx, trcObj.ISD, trcObj.Version)
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
			ISD:  1, Version: scrypto.LatestVer,
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
		},
		{
			Name: "unknown ISD=2, max version",
			ISD:  2, Version: scrypto.LatestVer,
			ExpData: trcs[2], ExpError: false,
		},
		{
			Name: "remote ISD=3, version 1",
			ISD:  3, Version: 1,
			ExpData: trcs[3], ExpError: false,
		},
		{
			Name: "remote ISD=3, max version",
			ISD:  3, Version: scrypto.LatestVer,
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
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		msger := newMessengerMock(ctrl, trcs, chains)
		store, cleanF := initStore(t, ctrl, xtest.MustParseIA("1-ff00:0:1"), msger)
		defer cleanF()

		insertTRC(t, store, trcs[1])
		insertTRC(t, store, trcs[3])

		for _, tc := range testCases[4:5] {
			Convey(tc.Name, func() {
				ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
				defer cancelF()
				trcObj, err := store.GetTRC(ctx, tc.ISD, tc.Version)
				xtest.SoMsgError("err", err, tc.ExpError)
				SoMsg("trc", trcObj, ShouldResemble, tc.ExpData)
			})
		}
	})

}

func TestGetValidChain(t *testing.T) {
	trcs, chains := loadCrypto(t, isds, ias)

	testCases := []struct {
		Name            string
		IA              addr.IA
		ExpData         *cert.Chain
		ExpError        bool
		DBChainInChecks []*cert.Chain // Check that these objects were saved to persistent storage
	}{
		{
			Name:    "bad IA=0-1",
			IA:      xtest.MustParseIA("0-ff00:0:1"),
			ExpData: nil, ExpError: true,
		},
		{
			Name:    "bad IA=1-0",
			IA:      addr.IA{I: 1, A: 0},
			ExpData: nil, ExpError: true,
		},
		{
			Name:    "local IA=1-1",
			IA:      xtest.MustParseIA("1-ff00:0:1"),
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ExpError: false,
		},
		{
			Name:    "remote IA=2-4",
			IA:      xtest.MustParseIA("2-ff00:0:4"),
			ExpData: chains[xtest.MustParseIA("2-ff00:0:4")], ExpError: false,
			DBChainInChecks: []*cert.Chain{chains[xtest.MustParseIA("2-ff00:0:4")]},
		},
	}

	Convey("Get Chains", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		msger := newMessengerMock(ctrl, trcs, chains)
		store, cleanF := initStore(t, ctrl, xtest.MustParseIA("1-ff00:0:1"), msger)
		defer cleanF()
		insertTRC(t, store, trcs[1])
		for _, tc := range testCases[3:4] {
			Convey(tc.Name, func() {
				ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
				defer cancelF()

				chain, err := store.GetValidChain(ctx, tc.IA, nil)
				xtest.SoMsgError("err", err, tc.ExpError)
				SoMsg("trc", chain, ShouldResemble, tc.ExpData)

				// Post-check DB state to verify insertion
				for _, chain := range tc.DBChainInChecks {
					get, err := store.trustdb.GetChainVersion(ctx, chain.Leaf.Subject,
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
		ExpData            *cert.Chain
		ExpError           bool
		DBChainNotInChecks []*cert.Chain // Check that these objects were not saved to DB
	}{
		{
			Name: "bad IA=0-1",
			IA:   xtest.MustParseIA("0-ff00:0:1"), Version: scrypto.LatestVer,
			ExpData: nil, ExpError: true,
		},
		{
			Name: "bad IA=1-0",
			IA:   addr.IA{I: 1, A: 0}, Version: scrypto.LatestVer,
			ExpData: nil, ExpError: true,
		},
		{
			Name: "local IA=1-1, version 1",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: 1,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ExpError: false,
		},
		{
			Name: "local IA=1-1, max version",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: scrypto.LatestVer,
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
			IA:   xtest.MustParseIA("3-ff00:0:9"), Version: scrypto.LatestVer,
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
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		msger := newMessengerMock(ctrl, trcs, chains)
		store, cleanF := initStore(t, ctrl, xtest.MustParseIA("1-ff00:0:1"), msger)
		defer cleanF()

		insertTRC(t, store, trcs[1])
		insertChain(t, store, chains[xtest.MustParseIA("1-ff00:0:1")])
		insertTRC(t, store, trcs[3])
		insertChain(t, store, chains[xtest.MustParseIA("3-ff00:0:9")])

		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
				defer cancelF()

				chain, err := store.GetChain(ctx, tc.IA, tc.Version)
				xtest.SoMsgError("err", err, tc.ExpError)
				SoMsg("trc", chain, ShouldResemble, tc.ExpData)

				// Post-check DB state to verify that unverified objects were not inserted
				for _, chain := range tc.DBChainNotInChecks {
					get, err := store.trustdb.GetChainVersion(ctx, chain.Leaf.Subject,
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
			ISD:  1, Version: scrypto.LatestVer,
			ExpData: trcs[1], ExpError: false,
			RecursionEnabled: true, CacheOnly: true,
		},
		{
			Name: "ask for known isd=1, version=max, cache-only, non-recursive",
			ISD:  1, Version: scrypto.LatestVer,
			ExpData: trcs[1], ExpError: false,
			RecursionEnabled: false, CacheOnly: true,
		},
		{
			Name: "ask for known isd=1, version=max, cache-only=false, recursive",
			ISD:  1, Version: scrypto.LatestVer,
			ExpData: trcs[1], ExpError: false,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for known isd=1, version=max, cache-only=false, non-recursive",
			ISD:  1, Version: scrypto.LatestVer,
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
			ISD:  2, Version: scrypto.LatestVer,
			ExpData: nil, ExpError: true,
			RecursionEnabled: true, CacheOnly: true,
		},
		{
			Name: "ask for unknown isd=2, version=max, cache-only, non-recursive",
			ISD:  2, Version: scrypto.LatestVer,
			ExpData: nil, ExpError: true,
			RecursionEnabled: false, CacheOnly: true,
		},
		{
			Name: "ask for unknown isd=2, version=max, cache-only=false, recursive",
			ISD:  2, Version: scrypto.LatestVer,
			ExpData: trcs[2], ExpError: false,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for known isd=2, version=max, cache-only=false, non-recursive",
			ISD:  2, Version: scrypto.LatestVer,
			ExpData: nil, ExpError: true,
			RecursionEnabled: false, CacheOnly: false,
		},
		{
			Name: "ask for bogus isd=42, version=max, cache-only=false, recursive",
			ISD:  42, Version: scrypto.LatestVer,
			ExpData: nil, ExpError: true,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for bogus isd=42, version=max, cache-only=true, non-recursive",
			ISD:  42, Version: scrypto.LatestVer,
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
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		msger := newMessengerMock(ctrl, trcs, chains)
		store, cleanF := initStore(t, ctrl, xtest.MustParseIA("1-ff00:0:1"), msger)
		defer cleanF()

		insertTRC(t, store, trcs[1])

		c2s, s2c := p2p.New()
		// each test initiates a request from the client messenger
		clientMessenger := setupMessenger(xtest.MustParseIA("2-ff00:0:1"), c2s, nil, "client")
		// the server messenger runs ListenAndServe, backed by the trust store
		serverMessenger := setupMessenger(xtest.MustParseIA("1-ff00:0:1"), s2c, store, "server")

		for _, tc := range testCases {
			Convey(tc.Name, func() {
				handler := store.NewTRCReqHandler(tc.RecursionEnabled)
				serverMessenger.AddHandler(infra.TRCRequest, handler)
				go func() {
					defer log.LogPanicAndExit()
					serverMessenger.ListenAndServe()
				}()
				defer serverMessenger.CloseServer()

				ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
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
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: scrypto.LatestVer,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ExpError: false,
			RecursionEnabled: true, CacheOnly: true,
		},
		{
			Name: "ask for known chain=1-1, version=max, cache-only, non-recursive",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: scrypto.LatestVer,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ExpError: false,
			RecursionEnabled: false, CacheOnly: true,
		},
		{
			Name: "ask for known chain=1-1, version=max, cache-only=false, recursive",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: scrypto.LatestVer,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ExpError: false,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for known chain=1-1, version=max, cache-only=false, non-recursive",
			IA:   xtest.MustParseIA("1-ff00:0:1"), Version: scrypto.LatestVer,
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
			IA:   xtest.MustParseIA("1-ff00:0:2"), Version: scrypto.LatestVer,
			ExpData: nil, ExpError: true,
			RecursionEnabled: true, CacheOnly: true,
		},
		{
			Name: "ask for unknown chain=1-2, version=max, cache-only, non-recursive",
			IA:   xtest.MustParseIA("1-ff00:0:2"), Version: scrypto.LatestVer,
			ExpData: nil, ExpError: true,
			RecursionEnabled: false, CacheOnly: true,
		},
		{
			Name: "ask for unknown chain=1-2, version=max, cache-only=false, recursive",
			IA:   xtest.MustParseIA("1-ff00:0:2"), Version: scrypto.LatestVer,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:2")], ExpError: false,
			RecursionEnabled: true, CacheOnly: false,
		},
		{
			Name: "ask for unknown chain=1-2, version=max, cache-only=false, non-recursive",
			IA:   xtest.MustParseIA("1-ff00:0:2"), Version: scrypto.LatestVer,
			ExpData: nil, ExpError: true,
			RecursionEnabled: false, CacheOnly: false,
		},
	}

	// See TestTRCReqHandler for info about the testing setup.
	Convey("Test ChainReq Handler", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		msger := newMessengerMock(ctrl, trcs, chains)
		store, cleanF := initStore(t, ctrl, xtest.MustParseIA("1-ff00:0:1"), msger)
		defer cleanF()

		insertTRC(t, store, trcs[1])
		insertChain(t, store, chains[xtest.MustParseIA("1-ff00:0:1")])

		c2s, s2c := p2p.New()
		// each test initiates a request from the client messenger
		clientMessenger := setupMessenger(xtest.MustParseIA("2-ff00:0:1"), c2s, nil, "client")
		// the server messenger runs ListenAndServe, backed by the trust store
		serverMessenger := setupMessenger(xtest.MustParseIA("1-ff00:0:1"), s2c, store, "server")

		for _, tc := range testCases {
			Convey(tc.Name, func() {
				handler := store.NewChainReqHandler(tc.RecursionEnabled)
				serverMessenger.AddHandler(infra.ChainRequest, handler)
				go func() {
					defer log.LogPanicAndExit()
					serverMessenger.ListenAndServe()
				}()
				defer serverMessenger.CloseServer()

				ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
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

func setupMessenger(ia addr.IA, conn net.PacketConn, store *Store, name string) infra.Messenger {
	transport := rpt.New(conn, log.New("name", name))
	dispatcher := disp.New(transport, messenger.DefaultAdapter, log.New("name", name))
	config := &messenger.Config{DisableSignatureVerification: true}
	return messenger.New(ia, dispatcher, store, log.Root().New("name", name), config)
}

func loadCrypto(t *testing.T, isds []addr.ISD,
	ias []addr.IA) (map[addr.ISD]*trc.TRC, map[addr.IA]*cert.Chain) {

	t.Helper()
	var err error

	trcMap := make(map[addr.ISD]*trc.TRC)
	for _, isd := range isds {
		trcMap[isd], err = trc.TRCFromFile(getTRCFileName(isd, 1), false)
		xtest.FailOnErr(t, err)
	}

	chainMap := make(map[addr.IA]*cert.Chain)
	for _, ia := range ias {
		chainMap[ia], err = cert.ChainFromFile(getChainFileName(ia, 1), false)
		xtest.FailOnErr(t, err)
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

func initStore(t *testing.T, ctrl *gomock.Controller,
	ia addr.IA, msger infra.Messenger) (*Store, func() error) {

	t.Helper()
	db, err := trustdbsqlite.New(":memory:")
	xtest.FailOnErr(t, err)
	topo := topology.NewTopo()
	topotestutil.AddServer(topo, proto.ServiceType_cs, "foo",
		topology.TestTopoAddr(nil, nil, nil, nil))
	itopo.SetCurrentTopology(topo)
	store, err := NewStore(db, ia, &Config{}, log.Root())
	xtest.FailOnErr(t, err)
	// Enable fake network access for trust database
	store.SetMessenger(msger)
	return store, db.Close
}

func insertTRC(t *testing.T, store *Store, trcObj *trc.TRC) {
	t.Helper()

	_, err := store.trustdb.InsertTRC(context.Background(), trcObj)
	xtest.FailOnErr(t, err)
}

func insertChain(t *testing.T, store *Store, chain *cert.Chain) {
	t.Helper()

	_, err := store.trustdb.InsertChain(context.Background(), chain)
	xtest.FailOnErr(t, err)
}
