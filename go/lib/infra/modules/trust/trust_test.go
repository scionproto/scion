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
	"os/exec"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb/trustdbsqlite"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/topology/topotestutil"
	"github.com/scionproto/scion/go/lib/xtest"
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
	cmd := exec.Command("tar", "-x", "-f", "testdata/crypto.tar", "-C", tmpDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		fmt.Println(err)
		os.Exit(1)
	}
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
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

func TestStoreGetTRC(t *testing.T) {
	trcs, chains := loadCrypto(t, isds, ias)

	tests := map[string]struct {
		ISD           addr.ISD
		Version       scrypto.Version
		ExpData       *trc.TRC
		ErrAssertion  require.ErrorAssertionFunc
		DBTRCInChecks []*trc.TRC // Check that these objects were saved to persistent storage
	}{
		"bad ISD=0": {
			ISD:          0,
			ExpData:      nil,
			ErrAssertion: require.Error,
		},
		"local ISD=1": {
			ISD:           1,
			ExpData:       trcs[1],
			ErrAssertion:  require.NoError,
			DBTRCInChecks: []*trc.TRC{trcs[1]},
		},
		"unknown ISD=6": {
			ISD:          6,
			ExpData:      nil,
			ErrAssertion: require.Error,
		},
		"local ISD=1, version 1": {

			ISD:          1,
			Version:      1,
			ExpData:      trcs[1],
			ErrAssertion: require.NoError,
		},
		"local ISD=1, max version": {

			ISD:          1,
			ExpData:      trcs[1],
			ErrAssertion: require.NoError,
		},
		"local ISD=1, unknown version": {

			ISD:          1,
			Version:      4,
			ExpData:      nil,
			ErrAssertion: require.Error,
		},
		"unknown ISD=2, version 1": {

			ISD:          2,
			Version:      1,
			ExpData:      trcs[2],
			ErrAssertion: require.NoError,
		},
		"unknown ISD=2, max version": {

			ISD:          2,
			ExpData:      trcs[2],
			ErrAssertion: require.NoError,
		},
		"remote ISD=3, version 1": {

			ISD:          3,
			Version:      1,
			ExpData:      trcs[3],
			ErrAssertion: require.NoError,
		},
		"remote ISD=3, max version": {

			ISD:          3,
			ExpData:      trcs[3],
			ErrAssertion: require.NoError,
		},
		"remote ISD=3, unknown version": {

			ISD:          3,
			Version:      4,
			ExpData:      nil,
			ErrAssertion: require.Error,
		},
		"bogus ISD=42": {

			ISD:          42,
			Version:      1,
			ExpData:      nil,
			ErrAssertion: require.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			msger := newMessengerMock(ctrl, trcs, chains)
			store, cleanF := initStore(t, ctrl, xtest.MustParseIA("1-ff00:0:1"), msger)
			defer cleanF()

			insertTRC(t, store, trcs[1])
			insertTRC(t, store, trcs[3])

			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()

			trcObj, err := store.GetTRC(ctx, test.ISD, test.Version, infra.TRCOpts{})
			test.ErrAssertion(t, err)
			assert.Equal(t, test.ExpData, trcObj)

			// Post-check DB state to verify insertion
			for _, trcObj := range test.DBTRCInChecks {
				get, err := store.trustdb.GetTRCVersion(ctx, trcObj.ISD, trcObj.Version)
				require.NoError(t, err)
				assert.Equal(t, trcObj, get)
			}
		})
	}
}

func TestStoreGetChain(t *testing.T) {
	trcs, chains := loadCrypto(t, isds, ias)

	tests := map[string]struct {
		IA              addr.IA
		Version         scrypto.Version
		ExpData         *cert.Chain
		ErrAssertion    require.ErrorAssertionFunc
		DBChainInChecks []*cert.Chain // Check that these objects were saved to persistent storage
	}{
		"bad IA=0-1": {
			IA:           xtest.MustParseIA("0-ff00:0:1"),
			ExpData:      nil,
			ErrAssertion: require.Error,
		},
		"bad IA=1-0": {
			IA:           addr.IA{I: 1, A: 0},
			ExpData:      nil,
			ErrAssertion: require.Error,
		},
		"local IA=1-1": {
			IA:           xtest.MustParseIA("1-ff00:0:1"),
			ExpData:      chains[xtest.MustParseIA("1-ff00:0:1")],
			ErrAssertion: require.NoError,
		},
		"remote IA=2-4": {
			IA:              xtest.MustParseIA("2-ff00:0:4"),
			ExpData:         chains[xtest.MustParseIA("2-ff00:0:4")],
			ErrAssertion:    require.NoError,
			DBChainInChecks: []*cert.Chain{chains[xtest.MustParseIA("2-ff00:0:4")]},
		},
		"local IA=1-1, version 1": {
			IA:           xtest.MustParseIA("1-ff00:0:1"),
			Version:      1,
			ExpData:      chains[xtest.MustParseIA("1-ff00:0:1")],
			ErrAssertion: require.NoError,
		},
		"local IA=1-1, unknown version 4": {
			IA:           xtest.MustParseIA("1-ff00:0:1"),
			Version:      4,
			ExpData:      nil,
			ErrAssertion: require.Error,
		},
		"unknown IA=2-4": {
			IA:              xtest.MustParseIA("2-ff00:0:4"),
			ExpData:         chains[xtest.MustParseIA("2-ff00:0:4")],
			ErrAssertion:    require.NoError,
			DBChainInChecks: []*cert.Chain{chains[xtest.MustParseIA("2-ff00:0:4")]},
		},
		"remote IA=3-9, version 1": {
			IA:           xtest.MustParseIA("3-ff00:0:9"),
			Version:      1,
			ExpData:      chains[xtest.MustParseIA("3-ff00:0:9")],
			ErrAssertion: require.NoError,
		},
		"remote IA=3-9, max version": {
			IA:           xtest.MustParseIA("3-ff00:0:9"),
			ExpData:      chains[xtest.MustParseIA("3-ff00:0:9")],
			ErrAssertion: require.NoError,
		},
		"remote IA=3-9, unknown version 4": {
			IA:           xtest.MustParseIA("3-ff00:0:9"),
			Version:      4,
			ExpData:      nil,
			ErrAssertion: require.Error,
		},
		"bogus IA=42-9": {
			IA:           xtest.MustParseIA("42-ff00:0:9"),
			Version:      1,
			ExpData:      nil,
			ErrAssertion: require.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			msger := newMessengerMock(ctrl, trcs, chains)
			store, cleanF := initStore(t, ctrl, xtest.MustParseIA("1-ff00:0:1"), msger)
			defer cleanF()

			insertTRC(t, store, trcs[1])
			insertChain(t, store, chains[xtest.MustParseIA("1-ff00:0:1")])
			insertTRC(t, store, trcs[3])
			insertChain(t, store, chains[xtest.MustParseIA("3-ff00:0:9")])

			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()

			chain, err := store.GetChain(ctx, test.IA, test.Version, infra.ChainOpts{})
			test.ErrAssertion(t, err)
			assert.Equal(t, test.ExpData, chain)

			// Post-check DB state to verify insertion
			for _, chain := range test.DBChainInChecks {
				get, err := store.trustdb.GetChainVersion(ctx, chain.Leaf.Subject,
					chain.Leaf.Version)
				require.NoError(t, err)
				assert.Equal(t, chain, get)
			}
		})
	}
}

func TestTRCReqHandler(t *testing.T) {
	trcs, chains := loadCrypto(t, isds, ias)

	tests := map[string]struct {
		Name             string
		ISD              addr.ISD
		Version          uint64
		ExpData          *trc.TRC
		ErrAssertion     require.ErrorAssertionFunc
		RecursionEnabled bool // Tell the server to recurse on unknown objects
		CacheOnly        bool // Tell the client to override server's recursion settings
	}{
		"ask for known isd=1, version=max, cache-only, recursive": {

			ISD: 1, Version: scrypto.LatestVer,
			ExpData: trcs[1], ErrAssertion: require.NoError,
			RecursionEnabled: true, CacheOnly: true,
		},
		"ask for known isd=1, version=max, cache-only, non-recursive": {

			ISD: 1, Version: scrypto.LatestVer,
			ExpData: trcs[1], ErrAssertion: require.NoError,
			RecursionEnabled: false, CacheOnly: true,
		},
		"ask for known isd=1, version=max, cache-only=false, recursive": {

			ISD: 1, Version: scrypto.LatestVer,
			ExpData: trcs[1], ErrAssertion: require.NoError,
			RecursionEnabled: true, CacheOnly: false,
		},
		"ask for known isd=1, version=max, cache-only=false, non-recursive": {

			ISD: 1, Version: scrypto.LatestVer,
			ExpData: trcs[1], ErrAssertion: require.NoError,
			RecursionEnabled: false, CacheOnly: false,
		},
		"ask for known isd=1, version=1, cache-only=false, recursive": {

			ISD: 1, Version: 1,
			ExpData: trcs[1], ErrAssertion: require.NoError,
			RecursionEnabled: true, CacheOnly: false,
		},
		"ask for known isd=1, bogus ver=4, cache-only=false, recursive": {

			ISD: 1, Version: 4,
			ExpData: nil, ErrAssertion: require.Error,
			RecursionEnabled: true, CacheOnly: false,
		},
		"ask for unknown isd=2, version=max, cache-only, recursive": {

			ISD: 2, Version: scrypto.LatestVer,
			ExpData: nil, ErrAssertion: require.NoError,
			RecursionEnabled: true, CacheOnly: true,
		},
		"ask for unknown isd=2, version=max, cache-only, non-recursive": {

			ISD: 2, Version: scrypto.LatestVer,
			ExpData: nil, ErrAssertion: require.NoError,
			RecursionEnabled: false, CacheOnly: true,
		},
		"ask for unknown isd=2, version=max, cache-only=false, recursive": {

			ISD: 2, Version: scrypto.LatestVer,
			ExpData: trcs[2], ErrAssertion: require.NoError,
			RecursionEnabled: true, CacheOnly: false,
		},
		"ask for known isd=2, version=max, cache-only=false, non-recursive": {

			ISD: 2, Version: scrypto.LatestVer,
			ExpData: nil, ErrAssertion: require.Error,
			RecursionEnabled: false, CacheOnly: false,
		},
		"ask for bogus isd=42, version=max, cache-only=false, recursive": {

			ISD: 42, Version: scrypto.LatestVer,
			ExpData: nil, ErrAssertion: require.Error,
			RecursionEnabled: true, CacheOnly: false,
		},
		"ask for bogus isd=42, version=max, cache-only=true, non-recursive": {

			ISD: 42, Version: scrypto.LatestVer,
			ExpData: nil, ErrAssertion: require.NoError,
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
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			msger := newMessengerMock(ctrl, trcs, chains)
			store, cleanF := initStore(t, ctrl, xtest.MustParseIA("1-ff00:0:1"), msger)
			defer cleanF()

			insertTRC(t, store, trcs[1])

			c2s, s2c := p2p.NewPacketConns()
			// each test initiates a request from the client messenger
			clientMessenger := setupMessenger(xtest.MustParseIA("2-ff00:0:1"), c2s, "client")
			// the server messenger runs ListenAndServe, backed by the trust store
			serverMessenger := setupMessenger(xtest.MustParseIA("1-ff00:0:1"), s2c, "server")

			handler := store.NewTRCReqHandler(test.RecursionEnabled)
			serverMessenger.AddHandler(infra.TRCRequest, handler)
			go func() {
				defer log.LogPanicAndExit()
				serverMessenger.ListenAndServe()
			}()
			defer serverMessenger.CloseServer()

			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()

			msg := &cert_mgmt.TRCReq{
				ISD:       test.ISD,
				Version:   test.Version,
				CacheOnly: test.CacheOnly,
			}
			reply, err := clientMessenger.GetTRC(ctx, msg, nil, 73)
			test.ErrAssertion(t, err)
			if reply != nil {
				trcObj, err := reply.TRC()
				require.NoError(t, err)
				assert.Equal(t, test.ExpData, trcObj)
			}
		})
	}
}

func TestChainReqHandler(t *testing.T) {
	trcs, chains := loadCrypto(t, isds, ias)

	tests := map[string]struct {
		IA               addr.IA
		Version          uint64
		ExpData          *cert.Chain
		ErrAssertion     require.ErrorAssertionFunc
		RecursionEnabled bool // Tell the server to recurse on unknown objects
		CacheOnly        bool // Tell the client to override server's recursion settings
	}{
		"ask for known chain=1-1, version=max, cache-only, recursive": {
			IA: xtest.MustParseIA("1-ff00:0:1"), Version: scrypto.LatestVer,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ErrAssertion: require.NoError,
			RecursionEnabled: true, CacheOnly: true,
		},
		"ask for known chain=1-1, version=max, cache-only, non-recursive": {
			IA: xtest.MustParseIA("1-ff00:0:1"), Version: scrypto.LatestVer,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ErrAssertion: require.NoError,
			RecursionEnabled: false, CacheOnly: true,
		},
		"ask for known chain=1-1, version=max, cache-only=false, recursive": {
			IA: xtest.MustParseIA("1-ff00:0:1"), Version: scrypto.LatestVer,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ErrAssertion: require.NoError,
			RecursionEnabled: true, CacheOnly: false,
		},
		"ask for known chain=1-1, version=max, cache-only=false, non-recursive": {
			IA: xtest.MustParseIA("1-ff00:0:1"), Version: scrypto.LatestVer,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ErrAssertion: require.NoError,
			RecursionEnabled: false, CacheOnly: false,
		},
		"ask for known chain=1-1, version=1, cache-only=false, recursive": {
			IA: xtest.MustParseIA("1-ff00:0:1"), Version: 1,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:1")], ErrAssertion: require.NoError,
			RecursionEnabled: true, CacheOnly: false,
		},
		"ask for known chain=1-1, version=4, cache-only=false, recursive": {
			IA: xtest.MustParseIA("1-ff00:0:1"), Version: 4,
			ExpData: nil, ErrAssertion: require.Error,
			RecursionEnabled: true, CacheOnly: false,
		},
		"ask for unknown chain=1-2, version=max, cache-only, recursive": {
			IA: xtest.MustParseIA("1-ff00:0:2"), Version: scrypto.LatestVer,
			ExpData: nil, ErrAssertion: require.NoError,
			RecursionEnabled: true, CacheOnly: true,
		},
		"ask for unknown chain=1-2, version=max, cache-only, non-recursive": {
			IA: xtest.MustParseIA("1-ff00:0:2"), Version: scrypto.LatestVer,
			ExpData: nil, ErrAssertion: require.NoError,
			RecursionEnabled: false, CacheOnly: true,
		},
		"ask for unknown chain=1-2, version=max, cache-only=false, recursive": {
			IA: xtest.MustParseIA("1-ff00:0:2"), Version: scrypto.LatestVer,
			ExpData: chains[xtest.MustParseIA("1-ff00:0:2")], ErrAssertion: require.NoError,
			RecursionEnabled: true, CacheOnly: false,
		},
		"ask for unknown chain=1-2, version=max, cache-only=false, non-recursive": {
			IA: xtest.MustParseIA("1-ff00:0:2"), Version: scrypto.LatestVer,
			ExpData: nil, ErrAssertion: require.Error,
			RecursionEnabled: false, CacheOnly: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			msger := newMessengerMock(ctrl, trcs, chains)
			store, cleanF := initStore(t, ctrl, xtest.MustParseIA("1-ff00:0:1"), msger)
			defer cleanF()

			insertTRC(t, store, trcs[1])
			insertChain(t, store, chains[xtest.MustParseIA("1-ff00:0:1")])

			c2s, s2c := p2p.NewPacketConns()
			// each test initiates a request from the client messenger
			clientMessenger := setupMessenger(xtest.MustParseIA("2-ff00:0:1"), c2s, "client")
			// the server messenger runs ListenAndServe, backed by the trust store
			serverMessenger := setupMessenger(xtest.MustParseIA("1-ff00:0:1"), s2c, "server")

			handler := store.NewChainReqHandler(test.RecursionEnabled)
			serverMessenger.AddHandler(infra.ChainRequest, handler)
			go func() {
				defer log.LogPanicAndExit()
				serverMessenger.ListenAndServe()
			}()
			defer serverMessenger.CloseServer()

			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()

			msg := &cert_mgmt.ChainReq{
				RawIA:     test.IA.IAInt(),
				Version:   test.Version,
				CacheOnly: test.CacheOnly,
			}
			reply, err := clientMessenger.GetCertChain(ctx, msg, nil, 73)
			test.ErrAssertion(t, err)
			if reply != nil {
				chain, err := reply.Chain()
				require.NoError(t, err)
				assert.Equal(t, test.ExpData, chain)
			}
		})
	}
}

func setupMessenger(ia addr.IA, conn net.PacketConn, name string) infra.Messenger {
	config := &messenger.Config{
		IA: ia,
		Dispatcher: disp.New(
			conn,
			messenger.DefaultAdapter,
			log.New("name", name),
		),
		AddressRewriter: &messenger.AddressRewriter{
			Router: &snet.BaseRouter{
				IA: ia,
			},
		},
		DisableSignatureVerification: true,
		Logger:                       log.Root().New("name", name),
	}
	return messenger.New(config)
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
	cfg := Config{
		TopoProvider: &xtest.TestTopoProvider{
			Topo: topo,
		},
	}
	store := NewStore(db, ia, cfg, log.Root())
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
