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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	"github.com/scionproto/scion/go/pkg/ca/renewal/grpc"
	renewalgrpc "github.com/scionproto/scion/go/pkg/ca/renewal/grpc"
	"github.com/scionproto/scion/go/pkg/ca/renewal/grpc/mock_grpc"
	"github.com/scionproto/scion/go/pkg/ca/renewal/mock_renewal"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
)

func TestLegacyHandleLegacyRequest(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signedReq, err := renewal.NewLegacyChainRenewalRequest(context.Background(), mockCSR.Raw,
		trust.Signer{
			PrivateKey: priv,
			Algorithm:  signed.ECDSAWithSHA256,
			ChainValidity: cppki.Validity{
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(time.Hour),
			},
			Expiration:   time.Now().Add(time.Hour - time.Minute),
			IA:           xtest.MustParseIA("1-ff00:0:111"),
			SubjectKeyID: mockChain[0].SubjectKeyId,
		},
	)
	require.NoError(t, err)

	tests := map[string]struct {
		Request      func(t *testing.T) *cppb.ChainRenewalRequest
		Verifier     func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier
		ChainBuilder func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder
		Signer       func(ctrl *gomock.Controller) renewalgrpc.Signer
		DB           func(ctrl *gomock.Controller) renewal.DB
		Metric       string
		Assertion    assert.ErrorAssertionFunc
		Code         codes.Code
	}{
		"invalid verification key ID": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				signedReq, err := renewal.NewLegacyChainRenewalRequest(context.Background(),
					mockCSR.Raw,
					trust.Signer{
						PrivateKey: priv,
						Algorithm:  signed.ECDSAWithSHA256,
						ChainValidity: cppki.Validity{
							NotBefore: time.Now(),
							NotAfter:  time.Now().Add(time.Hour),
						},
						Expiration:   time.Now().Add(time.Hour - time.Minute),
						IA:           xtest.MustParseIA("0-ff00:0:111"),
						SubjectKeyID: mockChain[0].SubjectKeyId,
					},
				)
				require.NoError(t, err)
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				return mock_grpc.NewMockRenewalRequestVerifier(ctrl)
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				return mock_grpc.NewMockChainBuilder(ctrl)
			},
			Signer: func(ctrl *gomock.Controller) renewalgrpc.Signer {
				return mock_grpc.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				return mock_renewal.NewMockDB(ctrl)
			},
			Assertion: assert.Error,
			Code:      codes.InvalidArgument,
			Metric:    "err_parse",
		},
		"db read error": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				return mock_grpc.NewMockRenewalRequestVerifier(ctrl)
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				return mock_grpc.NewMockChainBuilder(ctrl)
			},
			Signer: func(ctrl *gomock.Controller) renewalgrpc.Signer {
				return mock_grpc.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().ClientChains(gomock.Any(), chainQueryMatcher{
					IA:           xtest.MustParseIA("1-ff00:0:111"),
					SubjectKeyID: mockChain[0].SubjectKeyId,
				}).Return(nil, mockErr)
				return db
			},
			Assertion: assert.Error,
			Code:      codes.Unavailable,
			Metric:    "err_database",
		},
		"not client": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				return mock_grpc.NewMockRenewalRequestVerifier(ctrl)
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				return mock_grpc.NewMockChainBuilder(ctrl)
			},
			Signer: func(ctrl *gomock.Controller) renewalgrpc.Signer {
				return mock_grpc.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().ClientChains(gomock.Any(), chainQueryMatcher{
					IA:           xtest.MustParseIA("1-ff00:0:111"),
					SubjectKeyID: mockChain[0].SubjectKeyId,
				}).Return(nil, nil)
				return db
			},
			Assertion: assert.Error,
			Code:      codes.PermissionDenied,
			Metric:    "err_notfound",
		},
		"invalid signature": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyPbSignedRenewalRequest(
					context.Background(),
					signedReq.SignedRequest,
					[][]*x509.Certificate{mockChain},
				).Return(nil, mockErr)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				return mock_grpc.NewMockChainBuilder(ctrl)
			},
			Signer: func(ctrl *gomock.Controller) renewalgrpc.Signer {
				return mock_grpc.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().ClientChains(gomock.Any(), chainQueryMatcher{
					IA:           xtest.MustParseIA("1-ff00:0:111"),
					SubjectKeyID: mockChain[0].SubjectKeyId,
				}).Return([][]*x509.Certificate{mockChain}, nil)
				return db
			},
			Assertion: assert.Error,
			Code:      codes.InvalidArgument,
			Metric:    "err_verify",
		},
		"failed to build chain": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyPbSignedRenewalRequest(
					context.Background(),
					signedReq.SignedRequest,
					[][]*x509.Certificate{mockChain},
				).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				cb := mock_grpc.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(nil, mockErr)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) renewalgrpc.Signer {
				return mock_grpc.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().ClientChains(gomock.Any(), chainQueryMatcher{
					IA:           xtest.MustParseIA("1-ff00:0:111"),
					SubjectKeyID: mockChain[0].SubjectKeyId,
				}).Return([][]*x509.Certificate{mockChain}, nil)
				return db
			},
			Assertion: assert.Error,
			Code:      codes.Unavailable,
			Metric:    "err_internal",
		},
		"db write error": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyPbSignedRenewalRequest(
					context.Background(),
					signedReq.SignedRequest,
					[][]*x509.Certificate{mockChain},
				).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				cb := mock_grpc.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(mockIssuedChain, nil)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) renewalgrpc.Signer {
				return mock_grpc.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().ClientChains(gomock.Any(), chainQueryMatcher{
					IA:           xtest.MustParseIA("1-ff00:0:111"),
					SubjectKeyID: mockChain[0].SubjectKeyId,
				}).Return([][]*x509.Certificate{mockChain}, nil)
				db.EXPECT().InsertClientChain(gomock.Any(), mockIssuedChain).Return(false, mockErr)
				return db
			},
			Assertion: assert.Error,
			Code:      codes.Unavailable,
			Metric:    "err_database",
		},
		"failed to sign": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyPbSignedRenewalRequest(
					context.Background(),
					signedReq.SignedRequest,
					[][]*x509.Certificate{mockChain},
				).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				cb := mock_grpc.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(mockIssuedChain, nil)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) renewalgrpc.Signer {
				signer := mock_grpc.NewMockSigner(ctrl)
				signer.EXPECT().Sign(gomock.Any(), gomock.Any()).Return(nil, mockErr)
				return signer
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().ClientChains(gomock.Any(), chainQueryMatcher{
					IA:           xtest.MustParseIA("1-ff00:0:111"),
					SubjectKeyID: mockChain[0].SubjectKeyId,
				}).Return([][]*x509.Certificate{mockChain}, nil)
				db.EXPECT().InsertClientChain(gomock.Any(), mockIssuedChain)
				return db
			},
			Assertion: assert.Error,
			Code:      codes.Unavailable,
			Metric:    "err_internal",
		},
		"valid": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyPbSignedRenewalRequest(context.Background(),
					signedReq.SignedRequest, [][]*x509.Certificate{mockChain}).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				cb := mock_grpc.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(mockIssuedChain, nil)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) renewalgrpc.Signer {
				signer := mock_grpc.NewMockSigner(ctrl)
				signer.EXPECT().Sign(gomock.Any(), gomock.Any())
				return signer
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().ClientChains(gomock.Any(), chainQueryMatcher{
					IA:           xtest.MustParseIA("1-ff00:0:111"),
					SubjectKeyID: mockChain[0].SubjectKeyId,
				}).Return([][]*x509.Certificate{mockChain}, nil)
				db.EXPECT().InsertClientChain(gomock.Any(), mockIssuedChain)
				return db
			},
			Assertion: assert.NoError,
			Code:      codes.OK,
			Metric:    "ok_success",
		},
	}
	for name, tc := range tests {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctr := metrics.NewTestCounter()
			s := &renewalgrpc.Legacy{
				Verifier:     tc.Verifier(ctrl),
				ChainBuilder: tc.ChainBuilder(ctrl),
				Signer:       tc.Signer(ctrl),
				DB:           tc.DB(ctrl),
				Metrics: grpc.LegacyHandlerMetrics{
					DatabaseError: ctr.With("result", "err_database"),
					InternalError: ctr.With("result", "err_internal"),
					NotFoundError: ctr.With("result", "err_notfound"),
					ParseError:    ctr.With("result", "err_parse"),
					VerifyError:   ctr.With("result", "err_verify"),
					Success:       ctr.With("result", "ok_success"),
				},
			}
			_, err := s.HandleLegacyRequest(context.Background(), tc.Request(t))
			tc.Assertion(t, err)
			assert.Equal(t, tc.Code, status.Code(err))
			for _, res := range []string{
				"err_database",
				"err_internal",
				"err_unavailable",
				"err_notfound",
				"err_parse",
				"err_verify",
				"ok_success",
			} {
				expected := float64(0)
				if res == tc.Metric {
					expected = 1
				}
				assert.Equal(t, expected, metrics.CounterValue(ctr.With("result", res)), res)
			}
		})
	}
}
