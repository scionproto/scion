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
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
)

func TestLocalRouterChooseServer(t *testing.T) {
	ia122 := xtest.MustParseIA("1-ff00:0:122")

	tests := map[string]addr.ISD{
		"ISD local":  1,
		"Remote ISD": 2,
	}
	for name, isd := range tests {
		t.Run(name, func(t *testing.T) {
			localCS := &snet.SVCAddr{IA: ia122, SVC: addr.SvcCS}
			router := trust.LocalRouter{
				IA: localCS.IA,
			}
			routed, err := router.ChooseServer(context.Background(), isd)
			require.NoError(t, err)
			assert.Equal(t, localCS, routed)
		})
	}
}

func TestCSRouterChooseServer(t *testing.T) {
	ia110 := xtest.MustParseIA("1-ff00:0:110")
	ia210 := xtest.MustParseIA("2-ff00:0:210")

	tests := map[string]struct {
		ISD         addr.ISD
		Expect      func(*mock_trust.MockDB, *mock_snet.MockRouter, *mock_snet.MockPath)
		ExpectedErr error
	}{
		"ISD local": {
			ISD: 1,
			Expect: func(_ *mock_trust.MockDB, r *mock_snet.MockRouter, p *mock_snet.MockPath) {
				p.EXPECT().Path().AnyTimes().Return(spath.Path{Raw: []byte("isd local path")})
				p.EXPECT().Destination().AnyTimes().Return(ia110)
				p.EXPECT().UnderlayNextHop().AnyTimes().Return(nil)
				r.EXPECT().Route(gomock.Any(), addr.IA{I: 1}).Return(p, nil)
			},
		},
		"ISD local, Route error": {
			ISD: 1,
			Expect: func(_ *mock_trust.MockDB, r *mock_snet.MockRouter, p *mock_snet.MockPath) {
				r.EXPECT().Route(gomock.Any(), addr.IA{I: 1}).Return(
					nil, common.NewBasicError("unable to route", nil),
				)
			},
			ExpectedErr: common.NewBasicError("unable to route", nil),
		},
		"Remote ISD, Valid TRC": {
			ISD: 2,
			Expect: func(db *mock_trust.MockDB, r *mock_snet.MockRouter, p *mock_snet.MockPath) {
				future := time.Now().Add(time.Hour)
				db.EXPECT().SignedTRC(gomock.Any(),
					cppki.TRCID{ISD: addr.ISD(2)}).Return(
					cppki.SignedTRC{TRC: cppki.TRC{Validity: cppki.Validity{NotAfter: future}}},
					nil,
				)
				p.EXPECT().Path().AnyTimes().Return(spath.Path{Raw: []byte("remote ISD path")})
				p.EXPECT().Destination().AnyTimes().Return(ia210)
				p.EXPECT().UnderlayNextHop().AnyTimes().Return(nil)
				r.EXPECT().Route(gomock.Any(), addr.IA{I: 2}).Return(p, nil)
			},
		},
		"Remote ISD, TRC not found": {
			ISD: 2,
			Expect: func(db *mock_trust.MockDB, r *mock_snet.MockRouter, p *mock_snet.MockPath) {
				db.EXPECT().SignedTRC(gomock.Any(),
					cppki.TRCID{ISD: addr.ISD(2)}).Return(
					cppki.SignedTRC{}, nil,
				)
				p.EXPECT().Path().AnyTimes().Return(spath.Path{Raw: []byte("isd local path")})
				p.EXPECT().Destination().AnyTimes().Return(ia110)
				p.EXPECT().UnderlayNextHop().AnyTimes().Return(nil)
				r.EXPECT().Route(gomock.Any(), addr.IA{I: 1}).Return(p, nil)
			},
		},
		"Remote ISD, Expired TRC": {
			ISD: 2,
			Expect: func(db *mock_trust.MockDB, r *mock_snet.MockRouter, p *mock_snet.MockPath) {
				passed := time.Now().Add(-time.Second)
				db.EXPECT().SignedTRC(gomock.Any(),
					cppki.TRCID{ISD: addr.ISD(2)}).Return(
					cppki.SignedTRC{TRC: cppki.TRC{Validity: cppki.Validity{NotAfter: passed}}},
					nil,
				)
				p.EXPECT().Path().AnyTimes().Return(spath.Path{Raw: []byte("isd local path")})
				p.EXPECT().Destination().AnyTimes().Return(ia110)
				p.EXPECT().UnderlayNextHop().AnyTimes().Return(nil)
				r.EXPECT().Route(gomock.Any(), addr.IA{I: 1}).Return(p, nil)
			},
		},
		"Remote ISD, DB error": {
			ISD: 2,
			Expect: func(db *mock_trust.MockDB, r *mock_snet.MockRouter, p *mock_snet.MockPath) {
				db.EXPECT().SignedTRC(gomock.Any(),
					cppki.TRCID{ISD: addr.ISD(2)}).Return(
					cppki.SignedTRC{}, common.NewBasicError("DB error", nil),
				)
			},
			ExpectedErr: common.NewBasicError("DB error", nil),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			db := mock_trust.NewMockDB(mctrl)
			r, p := mock_snet.NewMockRouter(mctrl), mock_snet.NewMockPath(mctrl)
			test.Expect(db, r, p)
			router := trust.AuthRouter{
				ISD:    1,
				Router: r,
				DB:     db,
			}
			res, err := router.ChooseServer(context.Background(), test.ISD)
			if test.ExpectedErr != nil {
				xtest.AssertErrorsIs(t, err, test.ExpectedErr)
			} else {
				require.NoError(t, err)
				expected := &snet.SVCAddr{
					IA:      p.Destination(),
					Path:    p.Path(),
					NextHop: p.UnderlayNextHop(),
					SVC:     addr.SvcCS,
				}
				assert.Equal(t, expected, res)
			}
		})
	}
}
