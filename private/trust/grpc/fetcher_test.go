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

package grpc_test

import (
	"context"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	mock_cp "github.com/scionproto/scion/pkg/proto/control_plane/mock_control_plane"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
	trustgrpc "github.com/scionproto/scion/private/trust/grpc"
)

func TestFetcherChains(t *testing.T) {
	dir := genCrypto(t)
	chain110 := xtest.LoadChain(t, filepath.Join(dir, "/certs/ISD1-ASff00_0_110.pem"))
	chain112 := xtest.LoadChain(t, filepath.Join(dir, "/certs/ISD1-ASff00_0_112.pem"))
	ia110 := addr.MustParseIA("1-ff00:0:110")
	queryDate := chain110[0].NotBefore.Add(time.Hour)
	internal := serrors.New("internal")

	testCases := map[string]struct {
		Server    func(*gomock.Controller) *mock_cp.MockTrustMaterialServiceServer
		Query     trust.ChainQuery
		Assertion assert.ErrorAssertionFunc
		Expected  [][]*x509.Certificate
	}{
		"RPC fail": {
			Server: func(mctrl *gomock.Controller) *mock_cp.MockTrustMaterialServiceServer {
				srv := mock_cp.NewMockTrustMaterialServiceServer(mctrl)
				srv.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(nil, internal)
				return srv
			},
			Query: trust.ChainQuery{
				IA:           ia110,
				SubjectKeyID: chain110[0].SubjectKeyId,
				Validity: cppki.Validity{
					NotBefore: queryDate,
					NotAfter:  queryDate,
				},
			},
			Assertion: assert.Error,
		},
		"garbage chain": {
			Server: func(mctrl *gomock.Controller) *mock_cp.MockTrustMaterialServiceServer {
				srv := mock_cp.NewMockTrustMaterialServiceServer(mctrl)
				srv.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(
					&cppb.ChainsResponse{
						Chains: []*cppb.Chain{{}},
					},
					nil,
				)
				return srv
			},
			Query: trust.ChainQuery{
				IA:           ia110,
				SubjectKeyID: chain110[0].SubjectKeyId,
				Validity: cppki.Validity{
					NotBefore: queryDate,
					NotAfter:  queryDate,
				},
			},
			Assertion: assert.Error,
		},
		"mismatching subject": {
			Server: func(mctrl *gomock.Controller) *mock_cp.MockTrustMaterialServiceServer {
				srv := mock_cp.NewMockTrustMaterialServiceServer(mctrl)
				srv.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(
					&cppb.ChainsResponse{
						Chains: []*cppb.Chain{{
							AsCert: chain112[0].Raw,
							CaCert: chain112[1].Raw,
						}},
					},
					nil,
				)
				return srv
			},
			Query: trust.ChainQuery{
				IA:           ia110,
				SubjectKeyID: chain110[0].SubjectKeyId,
				Validity: cppki.Validity{
					NotBefore: queryDate,
					NotAfter:  queryDate,
				},
			},
			Assertion: assert.Error,
		},
		"reply wrong validity": {
			Server: func(mctrl *gomock.Controller) *mock_cp.MockTrustMaterialServiceServer {
				srv := mock_cp.NewMockTrustMaterialServiceServer(mctrl)
				srv.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(
					&cppb.ChainsResponse{
						Chains: []*cppb.Chain{{
							AsCert: chain110[0].Raw,
							CaCert: chain110[1].Raw,
						}},
					},
					nil,
				)
				return srv
			},
			Query: trust.ChainQuery{
				IA:           ia110,
				SubjectKeyID: chain110[0].SubjectKeyId,
				Validity: cppki.Validity{
					NotBefore: chain110[0].NotBefore.Add(-time.Hour),
					NotAfter:  chain110[0].NotBefore.Add(-time.Hour),
				},
			},
			Assertion: assert.Error,
		},
		"valid single chain": {
			Server: func(mctrl *gomock.Controller) *mock_cp.MockTrustMaterialServiceServer {
				srv := mock_cp.NewMockTrustMaterialServiceServer(mctrl)
				srv.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(
					&cppb.ChainsResponse{
						Chains: []*cppb.Chain{{
							AsCert: chain110[0].Raw,
							CaCert: chain110[1].Raw,
						}},
					},
					nil,
				)
				return srv
			},
			Query: trust.ChainQuery{
				IA:           ia110,
				SubjectKeyID: chain110[0].SubjectKeyId,
				Validity: cppki.Validity{
					NotBefore: queryDate,
					NotAfter:  queryDate,
				},
			},
			Assertion: assert.NoError,
			Expected:  [][]*x509.Certificate{chain110},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			svc := xtest.NewGRPCService()
			cppb.RegisterTrustMaterialServiceServer(svc.Server(), tc.Server(mctrl))
			svc.Start(t)

			f := trustgrpc.Fetcher{Dialer: svc}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			chains, err := f.Chains(ctx, tc.Query, &net.UDPAddr{})
			tc.Assertion(t, err)
			assert.Equal(t, tc.Expected, chains)
		})
	}
}

func TestFetcherTRC(t *testing.T) {
	dir := genCrypto(t)
	updated := xtest.LoadTRC(t, filepath.Join(dir, "/trcs/ISD1-B1-S2.trc"))

	testCases := map[string]struct {
		Server    func(*gomock.Controller) *mock_cp.MockTrustMaterialServiceServer
		ID        cppki.TRCID
		Assertion assert.ErrorAssertionFunc
		Expected  cppki.SignedTRC
	}{
		"RPC fail": {
			Server: func(mctrl *gomock.Controller) *mock_cp.MockTrustMaterialServiceServer {
				srv := mock_cp.NewMockTrustMaterialServiceServer(mctrl)
				srv.EXPECT().TRC(gomock.Any(), gomock.Any()).Return(
					nil, serrors.New("internal"),
				)
				return srv
			},
			ID:        updated.TRC.ID,
			Assertion: assert.Error,
		},
		"garbage TRC": {
			Server: func(mctrl *gomock.Controller) *mock_cp.MockTrustMaterialServiceServer {
				srv := mock_cp.NewMockTrustMaterialServiceServer(mctrl)
				srv.EXPECT().TRC(gomock.Any(), gomock.Any()).Return(
					&cppb.TRCResponse{
						Trc: []byte("garbage"), // nolint - name from published protobuf
					},
					nil,
				)
				return srv
			},
			ID:        updated.TRC.ID,
			Assertion: assert.Error,
		},
		"mismatching ID": {
			Server: func(mctrl *gomock.Controller) *mock_cp.MockTrustMaterialServiceServer {
				rawBase, err := os.ReadFile(filepath.Join(dir, "/trcs/ISD1-B1-S1.trc"))
				require.NoError(t, err)

				srv := mock_cp.NewMockTrustMaterialServiceServer(mctrl)
				srv.EXPECT().TRC(gomock.Any(), gomock.Any()).Return(
					&cppb.TRCResponse{Trc: rawBase}, nil, // nolint - name from published protobuf
				)
				return srv
			},
			ID:        updated.TRC.ID,
			Assertion: assert.Error,
		},
		"valid TRC": {
			Server: func(mctrl *gomock.Controller) *mock_cp.MockTrustMaterialServiceServer {
				srv := mock_cp.NewMockTrustMaterialServiceServer(mctrl)
				srv.EXPECT().TRC(gomock.Any(), gomock.Any()).Return(
					&cppb.TRCResponse{
						Trc: updated.Raw, // nolint - name from published protobuf
					},
					nil,
				)
				return srv
			},
			ID:        updated.TRC.ID,
			Assertion: assert.NoError,
			Expected:  updated,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			svc := xtest.NewGRPCService()
			cppb.RegisterTrustMaterialServiceServer(svc.Server(), tc.Server(mctrl))
			svc.Start(t)

			f := trustgrpc.Fetcher{Dialer: svc}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			trc, err := f.TRC(ctx, tc.ID, &net.UDPAddr{})
			tc.Assertion(t, err)
			assert.Equal(t, tc.Expected, trc)
		})
	}
}
