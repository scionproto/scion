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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	trust "github.com/scionproto/scion/go/lib/infra/modules/trust/v2"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/internal/decoded"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/mock_v2"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/serrors"
)

func TestResolverTRC(t *testing.T) {
	internal := serrors.New("internal")
	type mocks struct {
		DB       *mock_v2.MockDB
		Inserter *mock_v2.MockInserter
		RPC      *mock_v2.MockRPC
	}
	tests := map[string]struct {
		Expect      func(t *testing.T, m mocks) decoded.TRC
		TRCReq      trust.TRCReq
		ExpectedErr error
	}{
		"Fetch missing links successfully": {
			Expect: func(t *testing.T, m mocks) decoded.TRC {
				trcs := testTRCs(t, 1)
				m.DB.EXPECT().GetTRC(gomock.Any(), addr.ISD(1), scrypto.LatestVer).Return(
					trcs[1].TRC, nil,
				)
				m.RPC.EXPECT().GetTRC(gomock.Any(), &cert_mgmt.TRCReq{ISD: 1}, nil).Return(
					&cert_mgmt.TRC{RawTRC: trcs[4].Raw}, nil,
				)
				for i := scrypto.Version(2); i <= scrypto.Version(4); i++ {
					v := i
					req := &cert_mgmt.TRCReq{ISD: 1, Version: v}
					m.RPC.EXPECT().GetTRC(gomock.Any(), req, nil).Return(
						&cert_mgmt.TRC{RawTRC: trcs[req.Version].Raw}, nil,
					)
					m.Inserter.EXPECT().InsertTRC(gomock.Any(), trcs[v], gomock.Any()).DoAndReturn(
						func(_ interface{}, decTRC decoded.TRC, p trust.TRCProviderFunc) error {
							prev, err := p(nil, 1, v-1)
							require.NoError(t, err)
							assert.Equal(t, trcs[v-1].TRC, prev)
							assert.Equal(t, trcs[v], decTRC)
							return nil
						},
					)
				}
				return trcs[4]
			},
			TRCReq: trust.TRCReq{ISD: 1, Version: scrypto.LatestVer},
		},
		"DB error": {
			Expect: func(t *testing.T, m mocks) decoded.TRC {
				m.DB.EXPECT().GetTRC(gomock.Any(), addr.ISD(1), scrypto.LatestVer).Return(
					nil, internal,
				)
				return decoded.TRC{}
			},
			TRCReq:      trust.TRCReq{ISD: 1, Version: 2},
			ExpectedErr: internal,
		},
		"Superseded": {
			Expect: func(t *testing.T, m mocks) decoded.TRC {
				trcs := testTRCs(t, 1)
				m.DB.EXPECT().GetTRC(gomock.Any(), addr.ISD(1), scrypto.LatestVer).Return(
					trcs[3].TRC, nil,
				)
				return decoded.TRC{}
			},
			TRCReq:      trust.TRCReq{ISD: 1, Version: 2},
			ExpectedErr: trust.ErrResolveSuperseded,
		},
		"Resolve latest fails": {
			Expect: func(t *testing.T, m mocks) decoded.TRC {
				m.RPC.EXPECT().GetTRC(gomock.Any(), gomock.Any(), nil).Return(nil, internal)
				return decoded.TRC{}
			},
			TRCReq:      trust.TRCReq{ISD: 1, Version: scrypto.LatestVer},
			ExpectedErr: internal,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			m := mocks{
				DB:       mock_v2.NewMockDB(mctrl),
				Inserter: mock_v2.NewMockInserter(mctrl),
				RPC:      mock_v2.NewMockRPC(mctrl),
			}
			expected := test.Expect(t, m)
			r := trust.NewResolver(m.DB, m.Inserter, m.RPC)
			decTRC, err := r.TRC(context.Background(), test.TRCReq, nil)
			assert.Equal(t, expected, decTRC)
			if test.ExpectedErr != nil {
				require.Error(t, err)
				assert.Truef(t, xerrors.Is(err, test.ExpectedErr),
					"actual: %s\nexpected: %s", err, test.ExpectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// testTRCs returns a map of parsable TRCs. They are not verifiable.
// FIXME(roosd): Replace this with actual verifiable TRCs in the crypto tar.
func testTRCs(t *testing.T, isd addr.ISD) map[scrypto.Version]decoded.TRC {
	baseTRC := loadTRC(t, TRCDesc{ISD: isd, Version: 1})
	trcs := map[scrypto.Version]decoded.TRC{1: baseTRC}
	for i := scrypto.Version(2); i < scrypto.Version(5); i++ {
		update := *baseTRC.TRC
		update.Version = i
		enc, err := trc.Encode(&update)
		require.NoError(t, err)
		raw, err := trc.EncodeSigned(trc.Signed{
			Signatures: baseTRC.Signed.Signatures,
			EncodedTRC: enc,
		})
		require.NoError(t, err)
		trcs[i], err = decoded.DecodeTRC(raw)
		require.NoError(t, err)
	}
	return trcs
}
