// Copyright 2020 Anapaya Systems
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

package trust_test

import (
	"context"
	"crypto/x509"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
)

func TestFetchingProviderGetChains(t *testing.T) {
	if *update {
		t.Skip("test crypto is being updated")
	}
	trc := xtest.LoadTRC(t, filepath.Join(goldenDir, "ISD1/trcs/ISD1-B1-S1.trc"))
	valid := xtest.LoadChain(t,
		filepath.Join(goldenDir, "ISD1/ASff00_0_110/crypto/as/ISD1-ASff00_0_110.pem"))
	inactive := xtest.LoadChain(t,
		filepath.Join(goldenDir, "ISD1/ASff00_0_110/crypto/as/ISD1-ASff00_0_110.pem"))
	inactive[0].NotAfter = time.Now().Add(-time.Second)
	all := append([][]*x509.Certificate{valid}, inactive)

	query := trust.ChainQuery{
		IA:           xtest.MustParseIA("1-ff00:0:110"),
		Date:         time.Now(),
		SubjectKeyID: valid[0].SubjectKeyId,
	}

	testCases := map[string]struct {
		DB             func(t *testing.T, ctrl *gomock.Controller) trust.DB
		Recurser       func(t *testing.T, ctrl *gomock.Controller) trust.Recurser
		Router         func(t *testing.T, ctrl *gomock.Controller) trust.Router
		Fetcher        func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher
		Query          trust.ChainQuery
		Options        []trust.Option
		ErrAssertion   assert.ErrorAssertionFunc
		ExpectedChains [][]*x509.Certificate
	}{
		"ISD-AS wildcard": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				return mock_trust.NewMockDB(ctrl)
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Query: trust.ChainQuery{
				IA:           xtest.MustParseIA("1-0"),
				Date:         query.Date,
				SubjectKeyID: query.SubjectKeyID,
			},
			Options:      []trust.Option{trust.AllowInactive()},
			ErrAssertion: assert.Error,
		},
		"chain in database, allow inactive, subject key ID not set": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), chainQueryMatcher{
					ia: query.IA,
				}).Return(all, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Query: trust.ChainQuery{
				IA:   query.IA,
				Date: query.Date,
			},
			Options:        []trust.Option{trust.AllowInactive()},
			ErrAssertion:   assert.NoError,
			ExpectedChains: all,
		},
		"chain in database, allow inactive, time not set": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), chainQueryMatcher{
					ia:   query.IA,
					skid: query.SubjectKeyID}).Return(all, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Query: trust.ChainQuery{
				IA:           query.IA,
				SubjectKeyID: query.SubjectKeyID,
			},
			Options:        []trust.Option{trust.AllowInactive()},
			ErrAssertion:   assert.NoError,
			ExpectedChains: all,
		},
		"chain in database, allow inactive": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), chainQueryMatcher{
					ia:   query.IA,
					skid: query.SubjectKeyID}).Return(all, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Query:          query,
			Options:        []trust.Option{trust.AllowInactive()},
			ErrAssertion:   assert.NoError,
			ExpectedChains: all,
		},
		"chain in database, no inactive": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), chainQueryMatcher{
					ia:   query.IA,
					skid: query.SubjectKeyID}).Return(all, nil)
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(trc, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Query:          query,
			Options:        []trust.Option{},
			ErrAssertion:   assert.NoError,
			ExpectedChains: [][]*x509.Certificate{valid},
		},
		"chain remote, allow inactive": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), chainQueryMatcher{
					ia:   query.IA,
					skid: query.SubjectKeyID}).Return(nil, nil)
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(trc, nil)
				db.EXPECT().InsertChain(gomock.Any(), valid).Return(true, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(&net.UDPAddr{Port: 80}).Return(nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				r := mock_trust.NewMockRouter(ctrl)
				r.EXPECT().ChooseServer(gomock.Any(), addr.ISD(1)).Return(
					&net.UDPAddr{Port: 90}, nil)
				return r
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				f := mock_trust.NewMockFetcher(ctrl)
				f.EXPECT().Chains(gomock.Any(), query, &net.UDPAddr{Port: 90}).Return(all, nil)
				return f
			},
			Query: query,
			Options: []trust.Option{
				trust.Client(&net.UDPAddr{Port: 80}),
				trust.AllowInactive(),
			},
			ErrAssertion:   assert.NoError,
			ExpectedChains: [][]*x509.Certificate{valid},
		},
		"chain remote, no inactive": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), chainQueryMatcher{
					ia:   query.IA,
					skid: query.SubjectKeyID}).Return(nil, nil)
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(trc, nil)
				db.EXPECT().InsertChain(gomock.Any(), valid).Return(true, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				f := mock_trust.NewMockFetcher(ctrl)
				f.EXPECT().Chains(gomock.Any(), query, &net.UDPAddr{Port: 90}).Return(all, nil)
				return f
			},
			Query:          query,
			Options:        []trust.Option{trust.Server(&net.UDPAddr{Port: 90})},
			ErrAssertion:   assert.NoError,
			ExpectedChains: [][]*x509.Certificate{valid},
		},
		"no chain found": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), chainQueryMatcher{
					ia:   query.IA,
					skid: query.SubjectKeyID}).Return(nil, nil)
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(trc, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				f := mock_trust.NewMockFetcher(ctrl)
				f.EXPECT().Chains(gomock.Any(), query, &net.UDPAddr{Port: 90}).Return(nil, nil)
				return f
			},
			Query:        query,
			Options:      []trust.Option{trust.Server(&net.UDPAddr{Port: 90})},
			ErrAssertion: assert.NoError,
		},
		"TRC from db fails": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(nil, nil)
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(
					cppki.SignedTRC{}, serrors.New("internal"))
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Query:        query,
			ErrAssertion: assert.Error,
		},
		"TRC not in db": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(nil, nil)
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(cppki.SignedTRC{}, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Query:        query,
			ErrAssertion: assert.Error,
		},
		"chains from db fails": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(nil, serrors.New("internal"))
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Query:        query,
			ErrAssertion: assert.Error,
		},
		"recursion not allowed": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(nil, nil)
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(trc, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(serrors.New("not allowed"))
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Query:        query,
			ErrAssertion: assert.Error,
		},
		"router fails": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(nil, nil)
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(trc, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				r := mock_trust.NewMockRouter(ctrl)
				r.EXPECT().ChooseServer(gomock.Any(), addr.ISD(1)).Return(
					nil, serrors.New("internal"))
				return r
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Query:        query,
			ErrAssertion: assert.Error,
		},
		"fetcher fails": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(nil, nil)
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(trc, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				f := mock_trust.NewMockFetcher(ctrl)
				f.EXPECT().Chains(gomock.Any(), query, gomock.Any()).Return(
					nil, serrors.New("internal"))
				return f
			},
			Query:        query,
			Options:      []trust.Option{trust.Server(&net.UDPAddr{Port: 90})},
			ErrAssertion: assert.Error,
		},
		"insert fails": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(nil, nil)
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(trc, nil)
				db.EXPECT().InsertChain(gomock.Any(), valid).Return(
					false, serrors.New("internal"))
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				f := mock_trust.NewMockFetcher(ctrl)
				f.EXPECT().Chains(gomock.Any(), query, gomock.Any()).Return(all, nil)
				return f
			},
			Query:        query,
			Options:      []trust.Option{trust.Server(&net.UDPAddr{Port: 90})},
			ErrAssertion: assert.Error,
		},
		"reject forged chain": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().Chains(gomock.Any(), chainQueryMatcher{
					ia:   query.IA,
					skid: query.SubjectKeyID}).Return(nil, nil)
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(trc, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				f := mock_trust.NewMockFetcher(ctrl)
				forged := xtest.LoadChain(t,
					filepath.Join(goldenDir, "ISD1/ASff00_0_110/crypto/as/ISD1-ASff00_0_110.pem"))
				forged[0].Signature[30] ^= 0xFF
				f.EXPECT().Chains(gomock.Any(), query, &net.UDPAddr{Port: 90}).Return(
					[][]*x509.Certificate{forged}, nil,
				)
				return f
			},
			Query:        query,
			Options:      []trust.Option{trust.Server(&net.UDPAddr{Port: 90})},
			ErrAssertion: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			p := trust.FetchingProvider{
				DB:       tc.DB(t, mctrl),
				Recurser: tc.Recurser(t, mctrl),
				Fetcher:  tc.Fetcher(t, mctrl),
				Router:   tc.Router(t, mctrl),
			}
			c, err := p.GetChains(context.Background(), tc.Query, tc.Options...)
			tc.ErrAssertion(t, err)
			assert.Equal(t, tc.ExpectedChains, c)
		})
	}
}

func TestFetchingProviderNotifyTRC(t *testing.T) {
	if *update {
		t.Skip("test crypto is being updated")
	}
	base := xtest.LoadTRC(t, filepath.Join(goldenDir, "trcs/ISD1-B1-S1.trc"))
	updated := xtest.LoadTRC(t, filepath.Join(goldenDir, "trcs/ISD1-B1-S2.trc"))

	testCases := map[string]struct {
		ID           cppki.TRCID
		DB           func(t *testing.T, ctrl *gomock.Controller) trust.DB
		Recurser     func(t *testing.T, ctrl *gomock.Controller) trust.Recurser
		Router       func(t *testing.T, ctrl *gomock.Controller) trust.Router
		Fetcher      func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher
		Options      []trust.Option
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"no TRC in database": {
			ID: updated.TRC.ID,
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: scrypto.LatestVer, Serial: scrypto.LatestVer},
				).Return(cppki.SignedTRC{}, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Options:      []trust.Option{},
			ErrAssertion: assert.Error,
		},
		"TRC in database": {
			ID: updated.TRC.ID,
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: scrypto.LatestVer, Serial: scrypto.LatestVer},
				).Return(updated, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Options:      []trust.Option{},
			ErrAssertion: assert.NoError,
		},
		"newer TRC in database": {
			ID: base.TRC.ID,
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: scrypto.LatestVer, Serial: scrypto.LatestVer},
				).Return(updated, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Options:      []trust.Option{},
			ErrAssertion: assert.NoError,
		},
		"older TRC in database": {
			ID: updated.TRC.ID,
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: scrypto.LatestVer, Serial: scrypto.LatestVer},
				).Return(base, nil)
				db.EXPECT().InsertTRC(gomock.Any(), updated).Return(true, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				f := mock_trust.NewMockFetcher(ctrl)
				f.EXPECT().TRC(gomock.Any(), updated.TRC.ID, &net.UDPAddr{Port: 90}).Return(
					updated, nil,
				)
				return f
			},
			Options:      []trust.Option{trust.Server(&net.UDPAddr{Port: 90})},
			ErrAssertion: assert.NoError,
		},
		"different base TRC in database": {
			ID: cppki.TRCID{ISD: 1, Base: 2, Serial: 2},
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: scrypto.LatestVer, Serial: scrypto.LatestVer},
				).Return(updated, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Options:      []trust.Option{},
			ErrAssertion: assert.Error,
		},
		"db fails": {
			ID: updated.TRC.ID,
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: scrypto.LatestVer, Serial: scrypto.LatestVer},
				).Return(
					cppki.SignedTRC{}, serrors.New("internal"),
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Options:      []trust.Option{},
			ErrAssertion: assert.Error,
		},
		"recursion not allowed": {
			ID: updated.TRC.ID,
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: scrypto.LatestVer, Serial: scrypto.LatestVer},
				).Return(base, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(serrors.New("not allowed"))
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Options:      []trust.Option{},
			ErrAssertion: assert.Error,
		},
		"router fails": {
			ID: updated.TRC.ID,
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: scrypto.LatestVer, Serial: scrypto.LatestVer},
				).Return(base, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				r := mock_trust.NewMockRouter(ctrl)
				r.EXPECT().ChooseServer(gomock.Any(), addr.ISD(1)).Return(
					nil, serrors.New("internal"),
				)
				return r
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				return mock_trust.NewMockFetcher(ctrl)
			},
			Options:      []trust.Option{},
			ErrAssertion: assert.Error,
		},
		"fetcher fails": {
			ID: updated.TRC.ID,
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: scrypto.LatestVer, Serial: scrypto.LatestVer},
				).Return(base, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				f := mock_trust.NewMockFetcher(ctrl)
				f.EXPECT().TRC(gomock.Any(), updated.TRC.ID, &net.UDPAddr{Port: 90}).Return(
					cppki.SignedTRC{}, serrors.New("network failure"),
				)
				return f
			},
			Options:      []trust.Option{trust.Server(&net.UDPAddr{Port: 90})},
			ErrAssertion: assert.Error,
		},
		"reject forged TRC": {
			ID: updated.TRC.ID,
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: scrypto.LatestVer, Serial: scrypto.LatestVer},
				).Return(base, nil)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				f := mock_trust.NewMockFetcher(ctrl)

				forged := xtest.LoadTRC(t, filepath.Join(goldenDir, "trcs/ISD1-B1-S2.trc"))
				for i := range forged.SignerInfos {
					forged.SignerInfos[i].Signature[0] ^= 0xFF
				}
				f.EXPECT().TRC(gomock.Any(), updated.TRC.ID, &net.UDPAddr{Port: 90}).Return(
					forged, nil,
				)
				return f
			},
			Options:      []trust.Option{trust.Server(&net.UDPAddr{Port: 90})},
			ErrAssertion: assert.Error,
		},
		"insert fails": {
			ID: updated.TRC.ID,
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(
					gomock.Any(),
					cppki.TRCID{ISD: 1, Base: scrypto.LatestVer, Serial: scrypto.LatestVer},
				).Return(base, nil)
				db.EXPECT().InsertTRC(gomock.Any(), updated).Return(false, serrors.New("internal"))
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			Fetcher: func(t *testing.T, ctrl *gomock.Controller) trust.Fetcher {
				f := mock_trust.NewMockFetcher(ctrl)
				f.EXPECT().TRC(gomock.Any(), updated.TRC.ID, &net.UDPAddr{Port: 90}).Return(
					updated, nil,
				)
				return f
			},
			Options:      []trust.Option{trust.Server(&net.UDPAddr{Port: 90})},
			ErrAssertion: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			p := trust.FetchingProvider{
				DB:       tc.DB(t, mctrl),
				Recurser: tc.Recurser(t, mctrl),
				Fetcher:  tc.Fetcher(t, mctrl),
				Router:   tc.Router(t, mctrl),
			}
			err := p.NotifyTRC(context.Background(), tc.ID, tc.Options...)
			tc.ErrAssertion(t, err)
		})
	}
}
