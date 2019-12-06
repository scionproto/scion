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

	"github.com/scionproto/scion/go/lib/addr"
	trust "github.com/scionproto/scion/go/lib/infra/modules/trust/v2"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/internal/decoded"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/mock_v2"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
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
				m.DB.EXPECT().GetTRC(gomock.Any(), addr.ISD(1), scrypto.LatestVer).Return(
					loadTRC(t, trc1v1).TRC, nil,
				)
				req := trust.TRCReq{ISD: 1, Version: scrypto.LatestVer}
				m.RPC.EXPECT().GetTRC(gomock.Any(), req, nil).Return(loadTRC(t, trc1v4).Raw, nil)
				for _, desc := range []TRCDesc{trc1v2, trc1v3, trc1v4} {
					req := trust.TRCReq{ISD: desc.ISD, Version: desc.Version}
					dec := loadTRC(t, desc)
					m.RPC.EXPECT().GetTRC(gomock.Any(), req, nil).Return(dec.Raw, nil)
					m.Inserter.EXPECT().InsertTRC(gomock.Any(), dec, gomock.Any()).DoAndReturn(
						func(_ interface{}, decTRC decoded.TRC, p trust.TRCProviderFunc) error {
							prev, err := p(nil, 1, req.Version-1)
							require.NoError(t, err)
							assert.Equal(t, req.Version-1, prev.Version)
							assert.Equal(t, dec, decTRC)
							return nil
						},
					)
				}
				return loadTRC(t, trc1v4)
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
				m.DB.EXPECT().GetTRC(gomock.Any(), addr.ISD(1), scrypto.LatestVer).Return(
					loadTRC(t, trc1v3).TRC, nil,
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
			xtest.AssertErrorsIs(t, err, test.ExpectedErr)
			assert.Equal(t, expected, decTRC)
		})
	}
}
