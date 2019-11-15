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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/internal/decoded"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/mock_v2"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

func TestInserterInsertTRC(t *testing.T) {
	tests := map[string]struct {
		Expect      func(*mock_v2.MockDB, decoded.TRC)
		Unsafe      bool
		ExpectedErr error
	}{
		"Exists with same contents": {
			Expect: func(db *mock_v2.MockDB, decTRC decoded.TRC) {
				db.EXPECT().TRCExists(gomock.Any(), decTRC).Return(
					true, nil,
				)
			},
		},
		"Exists with different contents": {
			Expect: func(db *mock_v2.MockDB, decTRC decoded.TRC) {
				db.EXPECT().TRCExists(gomock.Any(), decTRC).Return(
					true, trust.ErrContentMismatch,
				)
			},
			ExpectedErr: trust.ErrContentMismatch,
		},
		"Base TRC and unsafe set": {
			Expect: func(db *mock_v2.MockDB, decTRC decoded.TRC) {
				db.EXPECT().TRCExists(gomock.Any(), decTRC).Return(
					false, nil,
				)
				db.EXPECT().InsertTRC(gomock.Any(), decTRC).Return(true, nil)
			},
			Unsafe: true,
		},
		"Base TRC and unsafe set, insert fail": {
			Expect: func(db *mock_v2.MockDB, decTRC decoded.TRC) {
				db.EXPECT().TRCExists(gomock.Any(), decTRC).Return(
					false, nil,
				)
				db.EXPECT().InsertTRC(gomock.Any(), decTRC).Return(
					false, trust.ErrContentMismatch,
				)
			},
			ExpectedErr: trust.ErrContentMismatch,
			Unsafe:      true,
		},
		"Base TRC and unsafe not set": {
			Expect: func(db *mock_v2.MockDB, decTRC decoded.TRC) {
				db.EXPECT().TRCExists(gomock.Any(), decTRC).Return(
					false, nil,
				)
			},
			ExpectedErr: trust.ErrBaseNotSupported,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			db := mock_v2.NewMockDB(mctrl)
			decoded := loadTRC(t, trc1v1)
			test.Expect(db, decoded)
			ins := trust.NewInserter(db, test.Unsafe)

			err := ins.InsertTRC(context.Background(), decoded, nil)
			if test.ExpectedErr != nil {
				require.Truef(t, xerrors.Is(err, test.ExpectedErr),
					"Expected: %s Actual: %s", test.ExpectedErr, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestInserterInsertChain(t *testing.T) {
	notFound := serrors.New("not found")
	tests := map[string]struct {
		Expect      func(*mock_v2.MockDB, decoded.Chain)
		ExpectedErr error
		TRCProvider trust.TRCProviderFunc
	}{
		"valid": {
			Expect: func(db *mock_v2.MockDB, dec decoded.Chain) {
				db.EXPECT().ChainExists(gomock.Any(), dec).Return(
					false, nil,
				)
				db.EXPECT().InsertChain(gomock.Any(), dec).Return(
					true, true, nil,
				)
			},
		},
		"exists with same contents": {
			Expect: func(db *mock_v2.MockDB, dec decoded.Chain) {
				db.EXPECT().ChainExists(gomock.Any(), dec).Return(
					true, nil,
				)
			},
		},
		"exists with different contents": {
			Expect: func(db *mock_v2.MockDB, dec decoded.Chain) {
				db.EXPECT().ChainExists(gomock.Any(), dec).Return(
					true, trust.ErrContentMismatch,
				)
			},
			ExpectedErr: trust.ErrContentMismatch,
		},
		"TRC not found": {
			Expect: func(db *mock_v2.MockDB, dec decoded.Chain) {
				db.EXPECT().ChainExists(gomock.Any(), dec).Return(
					false, nil,
				)
			},
			TRCProvider: func(context.Context, addr.ISD, scrypto.Version) (*trc.TRC, error) {
				return nil, notFound
			},
			ExpectedErr: notFound,
		},
		"insert fails": {
			Expect: func(db *mock_v2.MockDB, dec decoded.Chain) {
				db.EXPECT().ChainExists(gomock.Any(), dec).Return(
					false, nil,
				)
				db.EXPECT().InsertChain(gomock.Any(), dec).Return(
					false, false, trust.ErrContentMismatch,
				)
			},
			ExpectedErr: trust.ErrContentMismatch,
		},
		"invalid AS certificate": {
			Expect: func(db *mock_v2.MockDB, dec decoded.Chain) {
				db.EXPECT().ChainExists(gomock.Any(), dec).Return(
					false, nil,
				)
				dec.AS.Subject = addr.IA{}
			},
			ExpectedErr: trust.ErrValidation,
		},
		"invalid issuer certificate": {
			Expect: func(db *mock_v2.MockDB, dec decoded.Chain) {
				db.EXPECT().ChainExists(gomock.Any(), dec).Return(
					false, nil,
				)
				dec.Issuer.Subject = addr.IA{}
			},
			ExpectedErr: trust.ErrValidation,
		},
		"forged AS certificate": {
			Expect: func(db *mock_v2.MockDB, dec decoded.Chain) {
				db.EXPECT().ChainExists(gomock.Any(), dec).Return(
					false, nil,
				)
				dec.Chain.AS.Signature[0] ^= 0xFF
			},
			ExpectedErr: trust.ErrVerification,
		},
		"forged issuer certificate": {
			Expect: func(db *mock_v2.MockDB, dec decoded.Chain) {
				db.EXPECT().ChainExists(gomock.Any(), dec).Return(
					false, nil,
				)
				dec.Chain.Issuer.Signature[0] ^= 0xFF
			},
			ExpectedErr: trust.ErrVerification,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			db := mock_v2.NewMockDB(mctrl)
			decoded := loadChain(t, chain110v1)
			test.Expect(db, decoded)
			ins := trust.NewInserter(db, false)

			decTRC := loadTRC(t, trc1v1)
			p := func(ctx context.Context, isd addr.ISD, ver scrypto.Version) (*trc.TRC, error) {
				return decTRC.TRC, nil
			}
			if test.TRCProvider != nil {
				p = test.TRCProvider
			}

			err := ins.InsertChain(context.Background(), decoded, p)
			if test.ExpectedErr != nil {
				require.Truef(t, xerrors.Is(err, test.ExpectedErr),
					"Expected: %s Actual: %s", test.ExpectedErr, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFwdInserterInsertChain(t *testing.T) {
	internal := serrors.New("internal")
	type mocks struct {
		DB     *mock_v2.MockDB
		Router *mock_v2.MockRouter
		RPC    *mock_v2.MockRPC
	}
	tests := map[string]struct {
		Expect      func(*mocks, decoded.Chain)
		ExpectedErr error
		TRCProvider trust.TRCProviderFunc
	}{
		"valid": {
			Expect: func(m *mocks, dec decoded.Chain) {
				m.DB.EXPECT().ChainExists(gomock.Any(), dec).Return(
					false, nil,
				)
				a := snet.NewSVCAddr(addr.IA{}, nil, nil, addr.SvcCS)
				m.RPC.EXPECT().SendCertChain(gomock.Any(), dec.Raw, a).Return(nil)
				m.DB.EXPECT().InsertChain(gomock.Any(), dec).Return(
					true, true, nil,
				)
			},
		},
		"already exists": {
			Expect: func(m *mocks, dec decoded.Chain) {
				m.DB.EXPECT().ChainExists(gomock.Any(), dec).Return(
					true, nil,
				)
			},
		},
		"mismatch": {
			Expect: func(m *mocks, dec decoded.Chain) {
				m.DB.EXPECT().ChainExists(gomock.Any(), dec).Return(
					false, trust.ErrContentMismatch,
				)
			},
			ExpectedErr: trust.ErrContentMismatch,
		},
		"rpc fails": {
			Expect: func(m *mocks, dec decoded.Chain) {
				m.DB.EXPECT().ChainExists(gomock.Any(), dec).Return(
					false, nil,
				)
				a := snet.NewSVCAddr(addr.IA{}, nil, nil, addr.SvcCS)
				m.RPC.EXPECT().SendCertChain(gomock.Any(), dec.Raw, a).Return(internal)
			},
			ExpectedErr: internal,
		},
		"insert fails": {
			Expect: func(m *mocks, dec decoded.Chain) {
				m.DB.EXPECT().ChainExists(gomock.Any(), dec).Return(
					false, nil,
				)
				a := snet.NewSVCAddr(addr.IA{}, nil, nil, addr.SvcCS)
				m.RPC.EXPECT().SendCertChain(gomock.Any(), dec.Raw, a).Return(nil)
				m.DB.EXPECT().InsertChain(gomock.Any(), dec).Return(
					false, false, trust.ErrContentMismatch,
				)
			},
			ExpectedErr: trust.ErrContentMismatch,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			m := &mocks{
				DB:     mock_v2.NewMockDB(mctrl),
				RPC:    mock_v2.NewMockRPC(mctrl),
				Router: mock_v2.NewMockRouter(mctrl),
			}
			decoded := loadChain(t, chain110v1)
			test.Expect(m, decoded)
			ins := trust.NewFwdInserter(m.DB, m.RPC)

			decTRC := loadTRC(t, trc1v1)
			p := func(ctx context.Context, isd addr.ISD, ver scrypto.Version) (*trc.TRC, error) {
				return decTRC.TRC, nil
			}
			if test.TRCProvider != nil {
				p = test.TRCProvider
			}

			err := ins.InsertChain(context.Background(), decoded, p)
			if test.ExpectedErr != nil {
				require.Truef(t, xerrors.Is(err, test.ExpectedErr),
					"Expected: %s Actual: %s", test.ExpectedErr, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
