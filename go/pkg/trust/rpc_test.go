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
	"io/ioutil"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
)

func TestFetcherChain(t *testing.T) {
	if *update {
		t.Skip("test crypto is being updated")
	}
	chain110 := xtest.LoadChain(t, "testdata/common/certs/ISD1-ASff00_0_110.pem")
	chain112 := xtest.LoadChain(t, "testdata/common/certs/ISD1-ASff00_0_112.pem")
	ia110 := xtest.MustParseIA("1-ff00:0:110")
	queryDate := chain110[0].NotBefore.Add(time.Hour)
	internal := serrors.New("internal")

	testCases := map[string]struct {
		Expect    func(t *testing.T, rpc *mock_trust.MockRPC) [][]*x509.Certificate
		Query     trust.ChainQuery
		AssertErr assert.ErrorAssertionFunc
	}{
		"RPC fail": {
			Expect: func(t *testing.T, rpc *mock_trust.MockRPC) [][]*x509.Certificate {
				rpc.EXPECT().GetCertChain(gomock.Any(), gomock.Any(),
					gomock.Any(), gomock.Any()).Return(
					nil, internal,
				)
				return nil
			},
			Query: trust.ChainQuery{
				IA:           ia110,
				SubjectKeyID: chain110[0].SubjectKeyId,
				Date:         queryDate,
			},
			AssertErr: assert.Error,
		},
		"garbage chain": {
			Expect: func(t *testing.T, rpc *mock_trust.MockRPC) [][]*x509.Certificate {
				rpc.EXPECT().GetCertChain(gomock.Any(), gomock.Any(),
					gomock.Any(), gomock.Any()).Return(
					&cert_mgmt.Chain{RawChains: [][]byte{[]byte("garbage")}}, nil,
				)
				return nil
			},
			Query: trust.ChainQuery{
				IA:           ia110,
				SubjectKeyID: chain110[0].SubjectKeyId,
				Date:         queryDate,
			},
			AssertErr: assert.Error,
		},
		"mismatching subject": {
			Expect: func(t *testing.T, rpc *mock_trust.MockRPC) [][]*x509.Certificate {
				rpc.EXPECT().GetCertChain(gomock.Any(), gomock.Any(),
					gomock.Any(), gomock.Any()).Return(
					cert_mgmt.NewChain([][]*x509.Certificate{chain112}), nil,
				)
				return nil
			},
			Query: trust.ChainQuery{
				IA:           ia110,
				SubjectKeyID: chain110[0].SubjectKeyId,
				Date:         queryDate,
			},
			AssertErr: assert.Error,
		},
		"reply wrong validity": {
			Expect: func(t *testing.T, rpc *mock_trust.MockRPC) [][]*x509.Certificate {
				rpc.EXPECT().GetCertChain(gomock.Any(), gomock.Any(),
					gomock.Any(), gomock.Any()).Return(
					cert_mgmt.NewChain([][]*x509.Certificate{chain110}), nil,
				)
				return nil
			},
			Query: trust.ChainQuery{
				IA:           ia110,
				SubjectKeyID: chain110[0].SubjectKeyId,
				Date:         chain110[0].NotBefore.Add(-time.Hour),
			},
			AssertErr: assert.Error,
		},
		"valid single chain": {
			Expect: func(t *testing.T, rpc *mock_trust.MockRPC) [][]*x509.Certificate {
				rpc.EXPECT().GetCertChain(gomock.Any(), gomock.Any(),
					gomock.Any(), gomock.Any()).Return(
					cert_mgmt.NewChain([][]*x509.Certificate{chain110}), nil,
				)
				return [][]*x509.Certificate{chain110}
			},
			Query: trust.ChainQuery{
				IA:           ia110,
				SubjectKeyID: chain110[0].SubjectKeyId,
				Date:         queryDate,
			},
			AssertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			rpc := mock_trust.NewMockRPC(mctrl)
			expected := tc.Expect(t, rpc)
			r := trust.DefaultFetcher{
				RPC: rpc,
			}
			chain, err := r.Chains(context.Background(), tc.Query, nil)
			tc.AssertErr(t, err)
			assert.Equal(t, expected, chain)
		})
	}
}

func TestFetcherTRC(t *testing.T) {
	if *update {
		t.Skip("test crypto is being updated")
	}
	updated := xtest.LoadTRC(t, "testdata/common/trcs/ISD1-B1-S2.trc")

	testCases := map[string]struct {
		RPC       func(t *testing.T, mctrl *gomock.Controller) *mock_trust.MockRPC
		ID        cppki.TRCID
		AssertErr assert.ErrorAssertionFunc
		Expected  cppki.SignedTRC
	}{
		"RPC fail": {
			RPC: func(t *testing.T, mctrl *gomock.Controller) *mock_trust.MockRPC {
				r := mock_trust.NewMockRPC(mctrl)
				r.EXPECT().GetTRC(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
					nil, serrors.New("internal"),
				)
				return r
			},
			ID:        updated.TRC.ID,
			AssertErr: assert.Error,
		},
		"garbage TRC": {
			RPC: func(t *testing.T, mctrl *gomock.Controller) *mock_trust.MockRPC {
				r := mock_trust.NewMockRPC(mctrl)
				r.EXPECT().GetTRC(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
					&cert_mgmt.TRC{RawTRC: []byte("garbage")}, nil,
				)
				return r
			},
			ID:        updated.TRC.ID,
			AssertErr: assert.Error,
		},
		"mismatching ID": {
			RPC: func(t *testing.T, mctrl *gomock.Controller) *mock_trust.MockRPC {
				rawBase, err := ioutil.ReadFile("testdata/common/trcs/ISD1-B1-S1.trc")
				require.NoError(t, err)

				r := mock_trust.NewMockRPC(mctrl)
				r.EXPECT().GetTRC(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
					&cert_mgmt.TRC{RawTRC: rawBase}, nil,
				)
				return r
			},
			ID:        updated.TRC.ID,
			AssertErr: assert.Error,
		},
		"valid TRC": {
			RPC: func(t *testing.T, mctrl *gomock.Controller) *mock_trust.MockRPC {
				r := mock_trust.NewMockRPC(mctrl)
				r.EXPECT().GetTRC(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
					&cert_mgmt.TRC{RawTRC: updated.Raw}, nil,
				)
				return r
			},
			ID:        updated.TRC.ID,
			AssertErr: assert.NoError,
			Expected:  updated,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			r := trust.DefaultFetcher{
				RPC: tc.RPC(t, mctrl),
			}
			trc, err := r.TRC(context.Background(), tc.ID, nil)
			tc.AssertErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tc.Expected, trc)
		})
	}
}
