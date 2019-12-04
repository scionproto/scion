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
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/internal/decoded"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/mock_v2"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestCryptoProviderGetTRC(t *testing.T) {
	internal := serrors.New("internal")
	type mocks struct {
		DB       *mock_v2.MockDB
		Recurser *mock_v2.MockRecurser
		Resolver *mock_v2.MockResolver
		Router   *mock_v2.MockRouter
	}
	tests := map[string]struct {
		Expect      func(m *mocks, dec *decoded.TRC)
		Opts        infra.TRCOpts
		ExpectedErr error
	}{
		"TRC in database, allow inactive": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
					dec.Raw, nil,
				)
			},
			Opts: infra.TRCOpts{AllowInactive: true},
		},
		"TRC in database, is newest": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
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
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
					info, nil,
				)
			},
		},
		"not found, resolve success": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
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
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
					trust.TRCInfo{Version: dec.TRC.Version}, nil,
				)
			},
			ExpectedErr: trust.ErrInactive,
		},
		"TRC in database, invalidated by newer": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
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
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
					info, nil,
				)
			},
			ExpectedErr: trust.ErrInactive,
		},
		"DB error": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
					nil, internal,
				)
			},
			ExpectedErr: internal,
		},
		"Fail getting TRC info": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
					trust.TRCInfo{}, internal,
				)
			},
			ExpectedErr: internal,
		},
		"not found, local only": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
					nil, trust.ErrNotFound,
				)
			},
			Opts:        infra.TRCOpts{TrustStoreOpts: infra.TrustStoreOpts{LocalOnly: true}},
			ExpectedErr: trust.ErrNotFound,
		},
		"not found, recursion not allowed": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(internal)
			},
			ExpectedErr: internal,
		},
		"not found, router error": {
			Expect: func(m *mocks, dec *decoded.TRC) {
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
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
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
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
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, dec.TRC.Version).Return(
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
				DB:       mock_v2.NewMockDB(mctrl),
				Recurser: mock_v2.NewMockRecurser(mctrl),
				Resolver: mock_v2.NewMockResolver(mctrl),
				Router:   mock_v2.NewMockRouter(mctrl),
			}
			decoded := loadTRC(t, trc1v1)
			test.Expect(&m, &decoded)
			provider := trust.NewCryptoProvider(m.DB, m.Recurser, m.Resolver, m.Router)
			ptrc, err := provider.GetTRC(nil, trc1v1.ISD, trc1v1.Version, test.Opts)
			if test.ExpectedErr != nil {
				require.Error(t, err)
				assert.Truef(t, xerrors.Is(err, test.ExpectedErr),
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
		DB       *mock_v2.MockDB
		Recurser *mock_v2.MockRecurser
		Resolver *mock_v2.MockResolver
		Router   *mock_v2.MockRouter
	}
	tests := map[string]struct {
		Expect      func(m *mocks, dec *decoded.TRC) decoded.TRC
		Opts        infra.TRCOpts
		ExpectedErr error
	}{
		"TRC in database, allow inactive": {
			Expect: func(m *mocks, dec *decoded.TRC) decoded.TRC {
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
					dec.Raw, nil,
				)
				return *dec
			},
			Opts: infra.TRCOpts{AllowInactive: true},
		},
		"not found, resolve success": {
			Expect: func(m *mocks, dec *decoded.TRC) decoded.TRC {
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.Router.EXPECT().ChooseServer(gomock.Any(), dec.TRC.ISD).Return(ip, nil)
				req := trust.TRCReq{
					ISD:     dec.TRC.ISD,
					Version: scrypto.Version(scrypto.LatestVer),
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
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
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
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
					trust.TRCInfo{Version: dec.TRC.Version}, nil,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.Router.EXPECT().ChooseServer(gomock.Any(), dec.TRC.ISD).Return(ip, nil)
				req := trust.TRCReq{
					ISD:     dec.TRC.ISD,
					Version: scrypto.Version(scrypto.LatestVer),
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
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
					trust.TRCInfo{Version: dec.TRC.Version}, nil,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.Router.EXPECT().ChooseServer(gomock.Any(), dec.TRC.ISD).Return(ip, nil)
				req := trust.TRCReq{
					ISD:     dec.TRC.ISD,
					Version: scrypto.Version(scrypto.LatestVer),
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
				m.DB.EXPECT().GetRawTRC(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), dec.TRC.ISD, scrypto.LatestVer).Return(
					trust.TRCInfo{Version: dec.TRC.Version}, nil,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.Router.EXPECT().ChooseServer(gomock.Any(), dec.TRC.ISD).Return(ip, nil)
				req := trust.TRCReq{
					ISD:     dec.TRC.ISD,
					Version: scrypto.Version(scrypto.LatestVer),
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
				DB:       mock_v2.NewMockDB(mctrl),
				Recurser: mock_v2.NewMockRecurser(mctrl),
				Resolver: mock_v2.NewMockResolver(mctrl),
				Router:   mock_v2.NewMockRouter(mctrl),
			}
			decoded := loadTRC(t, trc1v1)
			expected := test.Expect(&m, &decoded)
			provider := trust.NewCryptoProvider(m.DB, m.Recurser, m.Resolver, m.Router)
			trcObj, err := provider.GetTRC(nil, trc1v1.ISD, scrypto.LatestVer, test.Opts)
			assert.Equal(t, expected.TRC, trcObj)
			if test.ExpectedErr != nil {
				require.Error(t, err)
				assert.Truef(t, xerrors.Is(err, test.ExpectedErr),
					"actual: %s expected: %s", err, test.ExpectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCryptoProviderGetRawChain(t *testing.T) {
	internal := serrors.New("internal")
	type mocks struct {
		DB       *mock_v2.MockDB
		Recurser *mock_v2.MockRecurser
		Resolver *mock_v2.MockResolver
		Router   *mock_v2.MockRouter
	}
	tests := map[string]struct {
		Run func(t *testing.T, m *mocks, p trust.CryptoProvider)
	}{
		"chain in database, allow inactive": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				dec := loadChain(t, chain110v1)
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					dec.Raw, nil,
				)
				opts := infra.ChainOpts{AllowInactive: true}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				require.NoError(t, err)
				assert.Equal(t, dec.Raw, raw)
			},
		},
		"not found, resolve success": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				dec := loadChain(t, chain110v1)
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.Router.EXPECT().ChooseServer(gomock.Any(), ia110.I).Return(ip, nil)
				req := trust.ChainReq{
					IA:        ia110,
					Version:   scrypto.Version(1),
					CacheOnly: false,
				}
				m.Resolver.EXPECT().Chain(gomock.Any(), req, ip).Return(dec, nil)
				opts := infra.ChainOpts{AllowInactive: true}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				require.NoError(t, err)
				assert.Equal(t, dec.Raw, raw)
			},
		},
		"latest TRC with same key version": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				dec := loadChain(t, chain110v1)
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					dec.Raw, nil,
				)
				trc := loadTRC(t, TRCDesc{ISD: ia110.I, Version: 1})
				m.DB.EXPECT().GetRawTRC(gomock.Any(), ia110.I, scrypto.LatestVer).Return(
					trc.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *trc.TRC.Validity, Version: 1}
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), ia110.I, scrypto.LatestVer).Return(info, nil)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: time.Hour,
							Version:     1,
						},
						Version: 1,
					}, nil,
				)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: time.Hour,
							Version:     2,
						},
						Version: 1,
					}, nil,
				)
				opts := infra.ChainOpts{}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				require.NoError(t, err)
				assert.Equal(t, dec.Raw, raw)
			},
		},
		"expired latest chain, fetch active latest": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				var err error
				fake := loadChain(t, chain110v1)
				fake.AS.Validity.NotAfter.Time = time.Now().Add(-time.Second)
				fake.Chain.AS.Encoded, err = cert.EncodeAS(fake.AS)
				require.NoError(t, err)
				raw, err := fake.Chain.MarshalJSON()
				require.NoError(t, err)

				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.LatestVer).Return(
					raw, nil,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.Router.EXPECT().ChooseServer(gomock.Any(), ia110.I).Return(ip, nil)
				req := trust.ChainReq{
					IA:        ia110,
					Version:   scrypto.LatestVer,
					CacheOnly: false,
				}
				dec := loadChain(t, chain110v1)
				m.Resolver.EXPECT().Chain(gomock.Any(), req, ip).Return(dec, nil)

				trc := loadTRC(t, TRCDesc{ISD: ia110.I, Version: 1})
				m.DB.EXPECT().GetRawTRC(gomock.Any(), ia110.I, scrypto.LatestVer).Return(
					trc.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *trc.TRC.Validity, Version: 1}
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), ia110.I, scrypto.LatestVer).Return(info, nil)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: time.Hour,
							Version:     1,
						},
						Version: 1,
					}, nil,
				)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: time.Hour,
							Version:     2,
						},
						Version: 1,
					}, nil,
				)
				opts := infra.ChainOpts{}
				raw, err = p.GetRawChain(nil, chain110v1.IA, scrypto.LatestVer, opts, nil)
				require.NoError(t, err)
				assert.Equal(t, dec.Raw, raw)
			},
		},
		"grace TRC with same key version": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				dec := loadChain(t, chain110v1)
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					dec.Raw, nil,
				)
				trc := loadTRC(t, TRCDesc{ISD: ia110.I, Version: 1})
				m.DB.EXPECT().GetRawTRC(gomock.Any(), ia110.I, scrypto.LatestVer).Return(
					trc.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *trc.TRC.Validity, Version: 1}
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), ia110.I, scrypto.LatestVer).Return(info, nil)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: time.Hour,
							Version:     1,
						},
						Version: 1,
					}, nil,
				)
				val := scrypto.Validity{
					NotBefore: util.UnixTime{Time: time.Now()},
					NotAfter:  util.UnixTime{Time: time.Now().Add(24 * time.Hour)},
				}
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    val,
							GracePeriod: time.Hour,
							Version:     3,
						},
						Version: 2,
					}, nil,
				)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.Version(2)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    val,
							GracePeriod: time.Hour,
							Version:     2,
						},
						Version: 1,
					}, nil,
				)
				opts := infra.ChainOpts{}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				require.NoError(t, err)
				assert.Equal(t, dec.Raw, raw)
			},
		},
		"latest TRC with different key version": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				dec := loadChain(t, chain110v1)
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					dec.Raw, nil,
				)
				trc := loadTRC(t, TRCDesc{ISD: ia110.I, Version: 1})
				m.DB.EXPECT().GetRawTRC(gomock.Any(), ia110.I, scrypto.LatestVer).Return(
					trc.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *trc.TRC.Validity, Version: 1}
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), ia110.I, scrypto.LatestVer).Return(info, nil)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: time.Hour,
							Version:     trc.TRC.Version,
						},
						Version: 1,
					}, nil,
				)
				val := scrypto.Validity{
					NotBefore: util.UnixTime{Time: time.Now().Add(-time.Hour)},
					NotAfter:  util.UnixTime{Time: time.Now().Add(24 * time.Hour)},
				}
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    val,
							GracePeriod: time.Second,
							Version:     2,
						},
						Version: 2,
					}, nil,
				)
				opts := infra.ChainOpts{}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				xtest.AssertErrorsIs(t, err, trust.ErrInactive)
				require.Error(t, err)
				assert.Nil(t, raw)
			},
		},
		"grace TRC with different key version": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				dec := loadChain(t, chain110v1)
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					dec.Raw, nil,
				)
				trc := loadTRC(t, TRCDesc{ISD: ia110.I, Version: 1})
				m.DB.EXPECT().GetRawTRC(gomock.Any(), ia110.I, scrypto.LatestVer).Return(
					trc.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *trc.TRC.Validity, Version: 1}
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), ia110.I, scrypto.LatestVer).Return(info, nil)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: time.Hour,
							Version:     trc.TRC.Version,
						},
						Version: 1,
					}, nil,
				)
				val := scrypto.Validity{
					NotBefore: util.UnixTime{Time: time.Now()},
					NotAfter:  util.UnixTime{Time: time.Now().Add(24 * time.Hour)},
				}
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    val,
							GracePeriod: time.Hour,
							Version:     3,
						},
						Version: 2,
					}, nil,
				)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.Version(2)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    val,
							GracePeriod: time.Hour,
							Version:     2,
						},
						Version: 2,
					}, nil,
				)
				opts := infra.ChainOpts{}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				xtest.AssertErrorsIs(t, err, trust.ErrInactive)
				require.Error(t, err)
				assert.Nil(t, raw)
			},
		},

		// Error cases
		"expired latest chain, fetch inactive": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				var err error
				fake := loadChain(t, chain110v1)
				fake.AS.Validity.NotAfter.Time = time.Now().Add(-time.Second)
				fake.Chain.AS.Encoded, err = cert.EncodeAS(fake.AS)
				require.NoError(t, err)
				raw, err := fake.Chain.MarshalJSON()
				require.NoError(t, err)

				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.LatestVer).Return(
					raw, nil,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.Router.EXPECT().ChooseServer(gomock.Any(), ia110.I).Return(ip, nil)
				req := trust.ChainReq{
					IA:        ia110,
					Version:   scrypto.LatestVer,
					CacheOnly: false,
				}
				m.Resolver.EXPECT().Chain(gomock.Any(), req, ip).Return(fake, nil)
				opts := infra.ChainOpts{}
				raw, err = p.GetRawChain(nil, chain110v1.IA, scrypto.LatestVer, opts, nil)
				xtest.AssertErrorsIs(t, err, trust.ErrInactive)
				assert.Nil(t, raw)
			},
		},
		"expired latest chain, fetch fails": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				var err error
				fake := loadChain(t, chain110v1)
				fake.AS.Validity.NotAfter.Time = time.Now().Add(-time.Second)
				fake.Chain.AS.Encoded, err = cert.EncodeAS(fake.AS)
				require.NoError(t, err)
				raw, err := fake.Chain.MarshalJSON()
				require.NoError(t, err)

				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.LatestVer).Return(
					raw, nil,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.Router.EXPECT().ChooseServer(gomock.Any(), ia110.I).Return(ip, nil)
				req := trust.ChainReq{
					IA:        ia110,
					Version:   scrypto.LatestVer,
					CacheOnly: false,
				}
				m.Resolver.EXPECT().Chain(gomock.Any(), req, ip).Return(decoded.Chain{}, internal)
				opts := infra.ChainOpts{}
				raw, err = p.GetRawChain(nil, chain110v1.IA, scrypto.LatestVer, opts, nil)
				xtest.AssertErrorsIs(t, err, internal)
				assert.Nil(t, raw)
			},
		},
		"failing to fetch TRC": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				dec := loadChain(t, chain110v1)
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					dec.Raw, nil,
				)
				m.DB.EXPECT().GetRawTRC(gomock.Any(), ia110.I, scrypto.LatestVer).Return(
					nil, internal,
				)
				opts := infra.ChainOpts{}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				xtest.AssertErrorsIs(t, err, internal)
				assert.Nil(t, raw)
			},
		},
		"failing to get key info for issuing TRC": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				dec := loadChain(t, chain110v1)
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					dec.Raw, nil,
				)
				trc := loadTRC(t, TRCDesc{ISD: ia110.I, Version: 1})
				m.DB.EXPECT().GetRawTRC(gomock.Any(), ia110.I, scrypto.LatestVer).Return(
					trc.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *trc.TRC.Validity, Version: 1}
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), ia110.I, scrypto.LatestVer).Return(info, nil)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{}, internal,
				)
				opts := infra.ChainOpts{}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				xtest.AssertErrorsIs(t, err, internal)
				assert.Nil(t, raw)
			},
		},
		"failing to get key info for latest TRC": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				dec := loadChain(t, chain110v1)
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					dec.Raw, nil,
				)
				trc := loadTRC(t, TRCDesc{ISD: ia110.I, Version: 1})
				m.DB.EXPECT().GetRawTRC(gomock.Any(), ia110.I, scrypto.LatestVer).Return(
					trc.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *trc.TRC.Validity, Version: 1}
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), ia110.I, scrypto.LatestVer).Return(info, nil)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: time.Hour,
							Version:     1,
						},
						Version: 1,
					}, nil,
				)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{}, internal,
				)
				opts := infra.ChainOpts{}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				xtest.AssertErrorsIs(t, err, internal)
				assert.Nil(t, raw)
			},
		},

		"failing to get key info for grace TRC": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				dec := loadChain(t, chain110v1)
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					dec.Raw, nil,
				)
				trc := loadTRC(t, TRCDesc{ISD: ia110.I, Version: 1})
				m.DB.EXPECT().GetRawTRC(gomock.Any(), ia110.I, scrypto.LatestVer).Return(
					trc.Raw, nil,
				)
				info := trust.TRCInfo{Validity: *trc.TRC.Validity, Version: 1}
				m.DB.EXPECT().GetTRCInfo(gomock.Any(), ia110.I, scrypto.LatestVer).Return(info, nil)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.Version(1)).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    info.Validity,
							GracePeriod: time.Hour,
							Version:     trc.TRC.Version,
						},
						Version: 1,
					}, nil,
				)
				val := scrypto.Validity{
					NotBefore: util.UnixTime{Time: time.Now()},
					NotAfter:  util.UnixTime{Time: time.Now().Add(24 * time.Hour)},
				}
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.LatestVer).Return(
					trust.KeyInfo{
						TRC: trust.TRCInfo{
							Validity:    val,
							GracePeriod: time.Hour,
							Version:     3,
						},
						Version: 2,
					}, nil,
				)
				m.DB.EXPECT().GetIssuingKeyInfo(gomock.Any(), ia110, scrypto.Version(2)).Return(
					trust.KeyInfo{}, internal,
				)
				opts := infra.ChainOpts{}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				xtest.AssertErrorsIs(t, err, internal)
				assert.Nil(t, raw)
			},
		},
		"database error": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					nil, internal,
				)
				opts := infra.ChainOpts{}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				xtest.AssertErrorsIs(t, err, internal)
				require.Error(t, err)
				assert.Nil(t, raw)
			},
		},
		"not found, local only": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					nil, trust.ErrNotFound,
				)
				opts := infra.ChainOpts{TrustStoreOpts: infra.TrustStoreOpts{LocalOnly: true}}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				xtest.AssertErrorsIs(t, err, trust.ErrNotFound)
				require.Error(t, err)
				assert.Nil(t, raw)
			},
		},
		"not found, recursion not allowed": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(internal)
				opts := infra.ChainOpts{}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				xtest.AssertErrorsIs(t, err, internal)
				require.Error(t, err)
				assert.Nil(t, raw)
			},
		},
		"not found, router error": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				m.Router.EXPECT().ChooseServer(gomock.Any(), ia110.I).Return(nil, internal)
				opts := infra.ChainOpts{}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				xtest.AssertErrorsIs(t, err, internal)
				require.Error(t, err)
				assert.Nil(t, raw)
			},
		},
		"not found, resolve error": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				m.Router.EXPECT().ChooseServer(gomock.Any(), ia110.I).Return(ip, nil)
				req := trust.ChainReq{
					IA:        ia110,
					Version:   scrypto.Version(1),
					CacheOnly: false,
				}
				m.Resolver.EXPECT().Chain(gomock.Any(), req, ip).Return(decoded.Chain{}, internal)
				opts := infra.ChainOpts{}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				xtest.AssertErrorsIs(t, err, internal)
				require.Error(t, err)
				assert.Nil(t, raw)
			},
		},
		"not found, server set": {
			Run: func(t *testing.T, m *mocks, p trust.CryptoProvider) {
				ip := &net.IPAddr{IP: []byte{127, 0, 0, 1}}
				m.DB.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.Version(1)).Return(
					nil, trust.ErrNotFound,
				)
				m.Recurser.EXPECT().AllowRecursion(gomock.Any()).Return(nil)
				req := trust.ChainReq{
					IA:        ia110,
					Version:   scrypto.Version(1),
					CacheOnly: true,
				}
				m.Resolver.EXPECT().Chain(gomock.Any(), req, ip).Return(decoded.Chain{}, internal)
				opts := infra.ChainOpts{
					TrustStoreOpts: infra.TrustStoreOpts{
						Server: &net.IPAddr{IP: []byte{127, 0, 0, 1}},
					},
				}
				raw, err := p.GetRawChain(nil, chain110v1.IA, chain110v1.Version, opts, nil)
				xtest.AssertErrorsIs(t, err, internal)
				require.Error(t, err)
				assert.Nil(t, raw)
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			m := &mocks{
				DB:       mock_v2.NewMockDB(mctrl),
				Recurser: mock_v2.NewMockRecurser(mctrl),
				Resolver: mock_v2.NewMockResolver(mctrl),
				Router:   mock_v2.NewMockRouter(mctrl),
			}
			p := trust.NewCryptoProvider(m.DB, m.Recurser, m.Resolver, m.Router, false)
			test.Run(t, m, p)
		})
	}
}
