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

package trust_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/mock_trust"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestCryptoProviderAnnounceTRC(t *testing.T) {
	internal := serrors.New("internal")
	type mocks struct {
		DB       *mock_trust.MockDB
		Recurser *mock_trust.MockRecurser
		Resolver *mock_trust.MockResolver
		Router   *mock_trust.MockRouter
	}
	tests := map[string]struct {
		Expect      func(m *mocks, dec *decoded.TRC)
		Opts        infra.TRCOpts
		ExpectedErr error
	}{
		"TRC in database": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					dec.Raw, nil,
				)
			},
			Opts: infra.TRCOpts{},
		},
		"not found, resolve success": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				req := trust.TRCReq{
					ISD:     dec.TRC.ISD,
					Version: dec.TRC.Version,
				}
				m.Resolver.EXPECT().TRC(gomock.Any(), req, ip).Return(*dec, nil)
			},
			Opts: infra.TRCOpts{
				TrustStoreOpts: infra.TrustStoreOpts{
					Server: &net.IPAddr{IP: []byte{127, 0, 0, 1}},
				},
			},
		},
		"DB error": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					nil, internal,
				)
			},
			ExpectedErr: internal,
		},
		"not found, local only": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					nil, trust.ErrNotFound,
				)
			},
			Opts:        infra.TRCOpts{TrustStoreOpts: infra.TrustStoreOpts{LocalOnly: true}},
			ExpectedErr: trust.ErrNotFound,
		},
		"not found, recursion not allowed": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(internal)
			},
			ExpectedErr: internal,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			m := mocks{
				DB:       mock_trust.NewMockDB(mctrl),
				Recurser: mock_trust.NewMockRecurser(mctrl),
				Resolver: mock_trust.NewMockResolver(mctrl),
				Router:   mock_trust.NewMockRouter(mctrl),
			}
			decoded := loadTRC(t, trc1v1)
			test.Expect(&m, &decoded)
			provider := trust.Provider{
				DB:       m.DB,
				Recurser: m.Recurser,
				Resolver: m.Resolver,
				Router:   m.Router,
			}
			id := trust.TRCID{ISD: trc1v1.ISD, Version: trc1v1.Version}
			err := provider.AnnounceTRC(context.Background(), id, test.Opts)
			xtest.AssertErrorsIs(t, err, test.ExpectedErr)
		})
	}
}

func TestCryptoProviderGetTRC(t *testing.T) {
	internal := serrors.New("internal")
	type mocks struct {
		DB       *mock_trust.MockDB
		Recurser *mock_trust.MockRecurser
		Resolver *mock_trust.MockResolver
		Router   *mock_trust.MockRouter
	}
	tests := map[string]struct {
		Expect      func(m *mocks, dec *decoded.TRC)
		Opts        infra.TRCOpts
		ExpectedErr error
	}{
		"TRC in database, allow inactive": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					dec.Raw, nil,
				)
			},
			Opts: infra.TRCOpts{AllowInactive: true},
		},
		"TRC in database, is newest": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					trust.TRCInfo{Version: dec.TRC.Version}, nil,
				)
			},
		},
		"TRC in database, within graceperiod": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				info := trust.TRCInfo{
					Version:     dec.TRC.Version + 1,
					GracePeriod: time.Hour,
					Validity:    scrypto.Validity{NotBefore: util.UnixTime{Time: time.Now()}},
				}
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					info, nil,
				)
			},
		},
		"not found, resolve success": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				req := trust.TRCReq{
					ISD:     dec.TRC.ISD,
					Version: dec.TRC.Version,
				}
				m.Resolver.EXPECT().TRC(gomock.Any(), req, ip).Return(*dec, nil)
			},
			Opts: infra.TRCOpts{
				TrustStoreOpts: infra.TrustStoreOpts{
					Server: &net.IPAddr{IP: []byte{127, 0, 0, 1}},
				},
				AllowInactive: true,
			},
		},
		"TRC in database, newest but expired": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				dec.TRC.Validity.NotAfter.Time = time.Now()
				dec.Signed.EncodedTRC, _ = trc.Encode(dec.TRC)
				dec.Raw, _ = json.Marshal(dec.Signed)
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					trust.TRCInfo{Version: dec.TRC.Version}, nil,
				)
			},
			ExpectedErr: trust.ErrInactive,
		},
		"TRC in database, invalidated by newer": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					trust.TRCInfo{Version: dec.TRC.Version + 2}, nil,
				)
			},
			ExpectedErr: trust.ErrInactive,
		},
		"TRC in database, outside graceperiod": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				info := trust.TRCInfo{
					Version:     dec.TRC.Version + 1,
					GracePeriod: time.Second,
					Validity: scrypto.Validity{
						NotBefore: util.UnixTime{Time: time.Now().Add(-2 * time.Second)},
					},
				}
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					info, nil,
				)
			},
			ExpectedErr: trust.ErrInactive,
		},
		"DB error": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					nil, internal,
				)
			},
			ExpectedErr: internal,
		},
		"Fail getting TRC info": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					trust.TRCInfo{}, internal,
				)
			},
			ExpectedErr: internal,
		},
		"not found, local only": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					nil, trust.ErrNotFound,
				)
			},
			Opts:        infra.TRCOpts{TrustStoreOpts: infra.TrustStoreOpts{LocalOnly: true}},
			ExpectedErr: trust.ErrNotFound,
		},
		"not found, recursion not allowed": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(internal)
			},
			ExpectedErr: internal,
		},
		"not found, router error": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				m.Router.EXPECT().ChooseServer(gomock.Any(), dec.TRC.ISD).Return(nil, internal)
			},
			ExpectedErr: internal,
		},
		"not found, resolve error": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				m.Router.EXPECT().ChooseServer(gomock.Any(), dec.TRC.ISD).Return(ip, nil)
				req := trust.TRCReq{
					ISD:     dec.TRC.ISD,
					Version: dec.TRC.Version,
				}
				m.Resolver.EXPECT().TRC(gomock.Any(), req, ip).Return(decoded.TRC{}, internal)
			},
			ExpectedErr: internal,
		},
		"not found, server set": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: dec.TRC.Version}).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				req := trust.TRCReq{
					ISD:     dec.TRC.ISD,
					Version: dec.TRC.Version,
				}
				m.Resolver.EXPECT().TRC(gomock.Any(), req, ip).Return(decoded.TRC{}, internal)
			},
			Opts: infra.TRCOpts{TrustStoreOpts: infra.TrustStoreOpts{
				Server: &net.IPAddr{IP: []byte{127, 0, 0, 1}}},
			},
			ExpectedErr: internal,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			m := mocks{
				DB:       mock_trust.NewMockDB(mctrl),
				Recurser: mock_trust.NewMockRecurser(mctrl),
				Resolver: mock_trust.NewMockResolver(mctrl),
				Router:   mock_trust.NewMockRouter(mctrl),
			}
			decoded := loadTRC(t, trc1v1)
			test.Expect(&m, &decoded)
			provider := trust.Provider{
				DB:       m.DB,
				Recurser: m.Recurser,
				Resolver: m.Resolver,
				Router:   m.Router,
			}
			id := trust.TRCID{ISD: trc1v1.ISD, Version: trc1v1.Version}
			ptrc, err := provider.GetTRC(context.Background(), id, test.Opts)
			if test.ExpectedErr != nil {
				require.Error(t, err)
				assert.Truef(t, errors.Is(err, test.ExpectedErr),
					"actual: %s expected: %s", err, test.ExpectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, decoded.TRC, ptrc)
			}
		})
	}
}

func TestCryptoProviderGetTRCLatest(t *testing.T) {
	internal := serrors.New("internal")
	type mocks struct {
		DB       *mock_trust.MockDB
		Recurser *mock_trust.MockRecurser
		Resolver *mock_trust.MockResolver
		Router   *mock_trust.MockRouter
	}
	tests := map[string]struct {
		Expect      func(m *mocks, dec *decoded.TRC) decoded.TRC
		Opts        infra.TRCOpts
		ExpectedErr error
	}{
		"TRC in database, allow inactive": {
			Expect: func(m *mocks, dec *decoded.TRC) decoded.TRC {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					dec.Raw, nil,
				)
				return *dec
			},
			Opts: infra.TRCOpts{AllowInactive: true},
		},
		"not found, resolve success": {
			Expect: func(m *mocks, dec *decoded.TRC) decoded.TRC {
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.Router.EXPECT().ChooseServer(gomock.Any(), dec.TRC.ISD).Return(ip, nil)
				req := trust.TRCReq{
					ISD:     dec.TRC.ISD,
					Version: scrypto.LatestVer,
				}
				m.Resolver.EXPECT().TRC(gomock.Any(), req, ip).Return(*dec, nil)
				return *dec
			},
			Opts: infra.TRCOpts{
				AllowInactive: true,
			},
		},
		"newest expired, recursion not allowed": {
			Expect: func(m *mocks, dec *decoded.TRC) decoded.TRC {
				dec.TRC.Validity.NotAfter.Time = time.Now()
				dec.Signed.EncodedTRC, _ = trc.Encode(dec.TRC)
				dec.Raw, _ = json.Marshal(dec.Signed)
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					trust.TRCInfo{Version: dec.TRC.Version}, nil,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(internal)
				return decoded.TRC{}
			},
			ExpectedErr: internal,
		},
		"newest expired, network returns same": {
			Expect: func(m *mocks, dec *decoded.TRC) decoded.TRC {
				dec.TRC.Validity.NotAfter.Time = time.Now()
				dec.Signed.EncodedTRC, _ = trc.Encode(dec.TRC)
				dec.Raw, _ = json.Marshal(dec.Signed)
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					trust.TRCInfo{Version: dec.TRC.Version}, nil,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.Router.EXPECT().ChooseServer(gomock.Any(), dec.TRC.ISD).Return(ip, nil)
				req := trust.TRCReq{
					ISD:     dec.TRC.ISD,
					Version: scrypto.LatestVer,
				}
				m.Resolver.EXPECT().TRC(gomock.Any(), req, ip).Return(*dec, nil)
				return decoded.TRC{}
			},
			ExpectedErr: trust.ErrInactive,
		},
		"newest expired, network returns expired": {
			Expect: func(m *mocks, dec *decoded.TRC) decoded.TRC {
				dec.TRC.Validity.NotAfter.Time = time.Now()
				dec.Signed.EncodedTRC, _ = trc.Encode(dec.TRC)
				dec.Raw, _ = json.Marshal(dec.Signed)
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					trust.TRCInfo{Version: dec.TRC.Version}, nil,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.Router.EXPECT().ChooseServer(gomock.Any(), dec.TRC.ISD).Return(ip, nil)
				req := trust.TRCReq{
					ISD:     dec.TRC.ISD,
					Version: scrypto.LatestVer,
				}
				newer := decoded.TRC{TRC: &(*dec.TRC)}
				newer.TRC.Version += 1
				newer.Signed.EncodedTRC, _ = trc.Encode(newer.TRC)
				newer.Raw, _ = json.Marshal(newer.Signed)
				m.Resolver.EXPECT().TRC(gomock.Any(), req, ip).Return(newer, nil)
				return decoded.TRC{}
			},
			ExpectedErr: trust.ErrInactive,
		},
		"newest expired, network returns newer": {
			Expect: func(m *mocks, dec *decoded.TRC) decoded.TRC {
				dec.TRC.Validity.NotAfter.Time = time.Now()
				dec.Signed.EncodedTRC, _ = trc.Encode(dec.TRC)
				dec.Raw, _ = json.Marshal(dec.Signed)
				m.DB.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: dec.TRC.ISD, Version: scrypto.LatestVer}).Return(
					trust.TRCInfo{Version: dec.TRC.Version}, nil,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.Router.EXPECT().ChooseServer(gomock.Any(), dec.TRC.ISD).Return(ip, nil)
				req := trust.TRCReq{
					ISD:     dec.TRC.ISD,
					Version: scrypto.LatestVer,
				}
				newer := decoded.TRC{TRC: &(*dec.TRC)}
				newer.TRC.Version += 1
				newer.TRC.Validity = &scrypto.Validity{
					NotAfter: util.UnixTime{Time: time.Now().Add(1000 * time.Hour)},
				}
				newer.Signed.EncodedTRC, _ = trc.Encode(newer.TRC)
				newer.Raw, _ = json.Marshal(newer.Signed)
				m.Resolver.EXPECT().TRC(gomock.Any(), req, ip).Return(newer, nil)
				return newer
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			m := mocks{
				DB:       mock_trust.NewMockDB(mctrl),
				Recurser: mock_trust.NewMockRecurser(mctrl),
				Resolver: mock_trust.NewMockResolver(mctrl),
				Router:   mock_trust.NewMockRouter(mctrl),
			}
			decoded := loadTRC(t, trc1v1)
			expected := test.Expect(&m, &decoded)
			provider := trust.Provider{
				DB:       m.DB,
				Recurser: m.Recurser,
				Resolver: m.Resolver,
				Router:   m.Router,
			}
			id := trust.TRCID{ISD: trc1v1.ISD, Version: scrypto.LatestVer}
			trcObj, err := provider.GetTRC(context.Background(), id, test.Opts)
			assert.Equal(t, expected.TRC, trcObj)
			if test.ExpectedErr != nil {
				require.Error(t, err)
				assert.Truef(t, errors.Is(err, test.ExpectedErr),
					"actual: %s expected: %s", err, test.ExpectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCryptoProviderGetRawChain(t *testing.T) {
	internal := serrors.New("internal")
	expired := func(t *testing.T, desc ChainDesc) decoded.Chain {
		t.Helper()
		var err error
		fake := loadChain(t, desc)
		fake.AS.Validity.NotAfter.Time = time.Now().Add(-time.Second)
		fake.Chain.AS.Encoded, err = cert.EncodeAS(fake.AS)
		require.NoError(t, err)
		fake.Raw, err = fake.Chain.MarshalJSON()
		require.NoError(t, err)
		return fake
	}
	dec110v1 := loadChain(t, chain110v1)
	tests := map[string]struct {
		DB          func(t *testing.T, ctrl *gomock.Controller) trust.DB
		Recurser    func(t *testing.T, ctrl *gomock.Controller) trust.Recurser
		Resolver    func(t *testing.T, ctrl *gomock.Controller) trust.Resolver
		Router      func(t *testing.T, ctrl *gomock.Controller) trust.Router
		ChainDesc   ChainDesc
		Opts        infra.ChainOpts
		ExpectedErr error
		ExpectedRaw []byte
	}{
		"chain in database, allow inactive": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					loadChain(t, chain110v1).Raw, nil,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{AllowInactive: true},
			ExpectedRaw: dec110v1.Raw,
		},
		"not found, resolve success": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					nil, trust.ErrNotFound,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				r := mock_trust.NewMockResolver(ctrl)
				req := trust.ChainReq{
					IA:      ia110,
					Version: scrypto.Version(1),
				}
				r.EXPECT().Chain(gomock.Any(), req, ip).Return(loadChain(t, chain110v1), nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				r := mock_trust.NewMockRouter(ctrl)
				r.EXPECT().ChooseServer(gomock.Any(), ia110.I).Return(ip, nil)
				return r
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{AllowInactive: true},
			ExpectedRaw: dec110v1.Raw,
		},
		"latest TRC with same key version": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					loadChain(t, chain110v1).Raw, nil,
				)
				dec := loadTRC(t, trc1v1)
				db.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(
					dec.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *dec.TRC.Validity, Version: 1}
				db.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(info, nil)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: 0,
							Version:     1,
						},
						Version: 1,
					}, nil,
				)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: time.Hour,
							Version:     2,
						},
						Version: 1,
					}, nil,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{},
			ExpectedRaw: dec110v1.Raw,
		},
		"expired latest chain, fetch active latest": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.LatestVer}).Return(
					expired(t, chain110v1).Raw, nil,
				)
				dec := loadTRC(t, trc1v1)
				db.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(
					dec.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *dec.TRC.Validity, Version: 1}
				db.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(info, nil)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: 0,
							Version:     1,
						},
						Version: 1,
					}, nil,
				)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: time.Hour,
							Version:     2,
						},
						Version: 1,
					}, nil,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				req := trust.ChainReq{
					IA:      ia110,
					Version: scrypto.LatestVer,
				}
				r := mock_trust.NewMockResolver(ctrl)
				r.EXPECT().Chain(gomock.Any(), req, ip).Return(loadChain(t, chain110v1), nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				r := mock_trust.NewMockRouter(ctrl)
				r.EXPECT().ChooseServer(gomock.Any(), ia110.I).Return(ip, nil)
				return r
			},
			ChainDesc:   ChainDesc{IA: ia110, Version: scrypto.LatestVer},
			Opts:        infra.ChainOpts{},
			ExpectedRaw: dec110v1.Raw,
		},
		"grace TRC with same key version": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					loadChain(t, chain110v1).Raw, nil,
				)
				dec := loadTRC(t, trc1v1)
				db.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(
					dec.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *dec.TRC.Validity, Version: 1}
				db.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(info, nil)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: 0,
							Version:     1,
						},
						Version: 1,
					}, nil,
				)
				val := scrypto.Validity{
					NotBefore: util.UnixTime{Time: time.Now()},
					NotAfter:  util.UnixTime{Time: time.Now().Add(24 * time.Hour)},
				}
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    val,
							GracePeriod: time.Hour,
							Version:     3,
						},
						Version: 2,
					}, nil,
				)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.Version(2)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    val,
							GracePeriod: time.Hour,
							Version:     2,
						},
						Version: 1,
					}, nil,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{},
			ExpectedRaw: dec110v1.Raw,
		},
		"latest TRC with different key version": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					loadChain(t, chain110v1).Raw, nil,
				)
				dec := loadTRC(t, trc1v1)
				db.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(
					dec.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *dec.TRC.Validity, Version: 1}
				db.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(info, nil)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: 0,
							Version:     1,
						},
						Version: 1,
					}, nil,
				)
				val := scrypto.Validity{
					NotBefore: util.UnixTime{Time: time.Now().Add(-time.Hour)},
					NotAfter:  util.UnixTime{Time: time.Now().Add(24 * time.Hour)},
				}
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    val,
							GracePeriod: time.Second,
							Version:     2,
						},
						Version: 2,
					}, nil,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{},
			ExpectedErr: trust.ErrInactive,
			ExpectedRaw: nil,
		},
		"grace TRC with different key version": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					loadChain(t, chain110v1).Raw, nil,
				)
				dec := loadTRC(t, trc1v1)
				db.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(
					dec.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *dec.TRC.Validity, Version: 1}
				db.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(info, nil)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: 0,
							Version:     1,
						},
						Version: 1,
					}, nil,
				)
				val := scrypto.Validity{
					NotBefore: util.UnixTime{Time: time.Now()},
					NotAfter:  util.UnixTime{Time: time.Now().Add(24 * time.Hour)},
				}
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    val,
							GracePeriod: time.Hour,
							Version:     3,
						},
						Version: 2,
					}, nil,
				)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.Version(2)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    val,
							GracePeriod: time.Hour,
							Version:     2,
						},
						Version: 2,
					}, nil,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{},
			ExpectedErr: trust.ErrInactive,
			ExpectedRaw: nil,
		},
		"expired latest chain, fetch inactive": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.LatestVer}).Return(
					expired(t, chain110v1).Raw, nil,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				req := trust.ChainReq{
					IA:      ia110,
					Version: scrypto.LatestVer,
				}
				r := mock_trust.NewMockResolver(ctrl)
				r.EXPECT().Chain(gomock.Any(), req, ip).Return(expired(t, chain110v1), nil)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				r := mock_trust.NewMockRouter(ctrl)
				r.EXPECT().ChooseServer(gomock.Any(), ia110.I).Return(ip, nil)
				return r
			},
			ChainDesc:   ChainDesc{IA: ia110, Version: scrypto.LatestVer},
			Opts:        infra.ChainOpts{},
			ExpectedErr: trust.ErrInactive,
			ExpectedRaw: nil,
		},
		"expired latest chain, fetch fails": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.LatestVer}).Return(
					expired(t, chain110v1).Raw, nil,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				req := trust.ChainReq{
					IA:      ia110,
					Version: scrypto.LatestVer,
				}
				r := mock_trust.NewMockResolver(ctrl)
				r.EXPECT().Chain(gomock.Any(), req, ip).Return(decoded.Chain{}, internal)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				r := mock_trust.NewMockRouter(ctrl)
				r.EXPECT().ChooseServer(gomock.Any(), ia110.I).Return(ip, nil)
				return r
			},
			ChainDesc:   ChainDesc{IA: ia110, Version: scrypto.LatestVer},
			Opts:        infra.ChainOpts{},
			ExpectedErr: internal,
			ExpectedRaw: nil,
		},
		"failing to fetch TRC": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					loadChain(t, chain110v1).Raw, nil,
				)
				db.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(
					nil, internal,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{},
			ExpectedErr: internal,
			ExpectedRaw: nil,
		},
		"failing to get key info for issuing TRC": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					loadChain(t, chain110v1).Raw, nil,
				)
				dec := loadTRC(t, trc1v1)
				db.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(
					dec.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *dec.TRC.Validity, Version: 1}
				db.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(info, nil)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{}, internal,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{},
			ExpectedErr: internal,
			ExpectedRaw: nil,
		},
		"failing to get key info for latest TRC": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					loadChain(t, chain110v1).Raw, nil,
				)
				dec := loadTRC(t, trc1v1)
				db.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(
					dec.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *dec.TRC.Validity, Version: 1}
				db.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(info, nil)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: 0,
							Version:     1,
						},
						Version: 1,
					}, nil,
				)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{}, internal,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{},
			ExpectedErr: internal,
			ExpectedRaw: nil,
		},

		"failing to get key info for grace TRC": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					loadChain(t, chain110v1).Raw, nil,
				)
				dec := loadTRC(t, trc1v1)
				db.EXPECT().GetRawTRC(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(
					dec.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *dec.TRC.Validity, Version: 1}
				db.EXPECT().GetTRCInfo(gomock.Any(),
					trust.TRCID{ISD: ia110.I, Version: scrypto.LatestVer}).Return(info, nil)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: 0,
							Version:     1,
						},
						Version: 1,
					}, nil,
				)
				val := scrypto.Validity{
					NotBefore: util.UnixTime{Time: time.Now()},
					NotAfter:  util.UnixTime{Time: time.Now().Add(24 * time.Hour)},
				}
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    val,
							GracePeriod: time.Hour,
							Version:     3,
						},
						Version: 2,
					}, nil,
				)
				db.EXPECT().GetIssuingGrantKeyInfo(gomock.Any(), ia110, scrypto.Version(2)).Return(
					trust.KeyInfo{}, internal,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{},
			ExpectedErr: internal,
			ExpectedRaw: nil,
		},
		"database error": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					nil, internal,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{},
			ExpectedErr: internal,
			ExpectedRaw: nil,
		},
		"not found, local only": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					nil, trust.ErrNotFound,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{TrustStoreOpts: infra.TrustStoreOpts{LocalOnly: true}},
			ExpectedErr: trust.ErrNotFound,
			ExpectedRaw: nil,
		},
		"not found, recursion not allowed": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					nil, trust.ErrNotFound,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(internal)
				return r
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{},
			ExpectedErr: internal,
			ExpectedRaw: nil,
		},
		"not found, router error": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					nil, trust.ErrNotFound,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				r := mock_trust.NewMockRouter(ctrl)
				r.EXPECT().ChooseServer(gomock.Any(), ia110.I).Return(nil, internal)
				return r
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{},
			ExpectedErr: internal,
			ExpectedRaw: nil,
		},
		"not found, resolve error": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					nil, trust.ErrNotFound,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				req := trust.ChainReq{
					IA:      ia110,
					Version: scrypto.Version(1),
				}
				r := mock_trust.NewMockResolver(ctrl)
				r.EXPECT().Chain(gomock.Any(), req, ip).Return(decoded.Chain{}, internal)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				r := mock_trust.NewMockRouter(ctrl)
				r.EXPECT().ChooseServer(gomock.Any(), ia110.I).Return(ip, nil)
				return r
			},
			ChainDesc:   chain110v1,
			Opts:        infra.ChainOpts{},
			ExpectedErr: internal,
			ExpectedRaw: nil,
		},
		"not found, server set": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					nil, trust.ErrNotFound,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				r := mock_trust.NewMockRecurser(ctrl)
				r.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				return r
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				req := trust.ChainReq{
					IA:      ia110,
					Version: scrypto.Version(1),
				}
				r := mock_trust.NewMockResolver(ctrl)
				r.EXPECT().Chain(gomock.Any(), req, ip).Return(decoded.Chain{}, internal)
				return r
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc: chain110v1,
			Opts: infra.ChainOpts{
				TrustStoreOpts: infra.TrustStoreOpts{
					Server: &net.IPAddr{IP: []byte{127, 0, 0, 1}},
				},
			},
			ExpectedErr: internal,
			ExpectedRaw: nil,
		},
	}
	for n, tc := range tests {
		name, test := n, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			p := trust.Provider{
				DB:       test.DB(t, mctrl),
				Recurser: test.Recurser(t, mctrl),
				Resolver: test.Resolver(t, mctrl),
				Router:   test.Router(t, mctrl),
			}
			id := trust.ChainID{IA: test.ChainDesc.IA, Version: test.ChainDesc.Version}
			raw, err := p.GetRawChain(context.Background(), id, test.Opts)
			xtest.AssertErrorsIs(t, err, test.ExpectedErr)
			assert.Equal(t, test.ExpectedRaw, raw)
		})
	}
}

func TestCryptoProviderGetASKey(t *testing.T) {
	internal := serrors.New("internal")
	dec110v1 := loadChain(t, chain110v1)
	tests := map[string]struct {
		DB              func(t *testing.T, ctrl *gomock.Controller) trust.DB
		Recurser        func(t *testing.T, ctrl *gomock.Controller) trust.Recurser
		Resolver        func(t *testing.T, ctrl *gomock.Controller) trust.Resolver
		Router          func(t *testing.T, ctrl *gomock.Controller) trust.Router
		ChainDesc       ChainDesc
		Opts            infra.ChainOpts
		ExpectedErr     error
		ExpectedKeyMeta scrypto.KeyMeta
	}{
		"chain in database, allow inactive": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					dec110v1.Raw, nil,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:       chain110v1,
			Opts:            infra.ChainOpts{AllowInactive: true},
			ExpectedKeyMeta: dec110v1.AS.Keys[cert.SigningKey],
		},
		"database error": {
			DB: func(t *testing.T, ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().GetRawChain(gomock.Any(),
					trust.ChainID{IA: ia110, Version: scrypto.Version(1)}).Return(
					nil, internal,
				)
				return db
			},
			Recurser: func(t *testing.T, ctrl *gomock.Controller) trust.Recurser {
				return mock_trust.NewMockRecurser(ctrl)
			},
			Resolver: func(t *testing.T, ctrl *gomock.Controller) trust.Resolver {
				return mock_trust.NewMockResolver(ctrl)
			},
			Router: func(t *testing.T, ctrl *gomock.Controller) trust.Router {
				return mock_trust.NewMockRouter(ctrl)
			},
			ChainDesc:       chain110v1,
			Opts:            infra.ChainOpts{},
			ExpectedErr:     internal,
			ExpectedKeyMeta: scrypto.KeyMeta{},
		},
	}
	for n, tc := range tests {
		name, test := n, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			p := trust.Provider{
				DB:       test.DB(t, mctrl),
				Recurser: test.Recurser(t, mctrl),
				Resolver: test.Resolver(t, mctrl),
				Router:   test.Router(t, mctrl),
			}
			id := trust.ChainID{IA: test.ChainDesc.IA, Version: test.ChainDesc.Version}
			km, err := p.GetASKey(context.Background(), id, test.Opts)
			xtest.AssertErrorsIs(t, err, test.ExpectedErr)
			assert.Equal(t, test.ExpectedKeyMeta, km)
		})
	}
}
