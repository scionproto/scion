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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	trustgrpc "github.com/scionproto/scion/go/pkg/cs/trust/grpc"
	"github.com/scionproto/scion/go/pkg/cs/trust/grpc/mock_grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
	"github.com/scionproto/scion/go/pkg/trust/renewal/mock_renewal"
)

func TestChainRenewalRequestHandle(t *testing.T) {
	mockErr := serrors.New("send error")
	mockCSR := &x509.CertificateRequest{
		Raw: []byte("mock CSR"),
		Subject: pkix.Name{Names: []pkix.AttributeTypeAndValue{{
			Type:  cppki.OIDNameIA,
			Value: "1-ff00:0:111",
		}}},
	}
	mockChain := []*x509.Certificate{
		{
			Raw:          []byte("mock AS cert"),
			SubjectKeyId: []byte("mock cert subject key"),
		},
		{Raw: []byte("mock CA cert")},
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signedReq, err := renewal.NewChainRenewalRequest(context.Background(), mockCSR.Raw,
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

	mockIssuedChain := []*x509.Certificate{
		{Raw: []byte("mock issued AS cert")},
		{Raw: []byte("mock CA cert")},
	}
	tests := map[string]struct {
		Request      func(t *testing.T) *cppb.ChainRenewalRequest
		Verifier     func(ctrl *gomock.Controller) trustgrpc.RenewalRequestVerifier
		ChainBuilder func(ctrl *gomock.Controller) trustgrpc.ChainBuilder
		Signer       func(ctrl *gomock.Controller) trustgrpc.Signer
		DB           func(ctrl *gomock.Controller) renewal.DB
		Assertion    assert.ErrorAssertionFunc
		Code         codes.Code
	}{
		"invalid verification key ID": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				signedReq, err := renewal.NewChainRenewalRequest(context.Background(), mockCSR.Raw,
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
			Verifier: func(ctrl *gomock.Controller) trustgrpc.RenewalRequestVerifier {
				return mock_grpc.NewMockRenewalRequestVerifier(ctrl)
			},
			ChainBuilder: func(ctrl *gomock.Controller) trustgrpc.ChainBuilder {
				return mock_grpc.NewMockChainBuilder(ctrl)
			},
			Signer: func(ctrl *gomock.Controller) trustgrpc.Signer {
				return mock_grpc.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				return mock_renewal.NewMockDB(ctrl)
			},
			Assertion: assert.Error,
			Code:      codes.InvalidArgument,
		},
		"db read error": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) trustgrpc.RenewalRequestVerifier {
				return mock_grpc.NewMockRenewalRequestVerifier(ctrl)
			},
			ChainBuilder: func(ctrl *gomock.Controller) trustgrpc.ChainBuilder {
				return mock_grpc.NewMockChainBuilder(ctrl)
			},
			Signer: func(ctrl *gomock.Controller) trustgrpc.Signer {
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
		},
		"not client": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) trustgrpc.RenewalRequestVerifier {
				return mock_grpc.NewMockRenewalRequestVerifier(ctrl)
			},
			ChainBuilder: func(ctrl *gomock.Controller) trustgrpc.ChainBuilder {
				return mock_grpc.NewMockChainBuilder(ctrl)
			},
			Signer: func(ctrl *gomock.Controller) trustgrpc.Signer {
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
		},
		"invalid signature": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) trustgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyChainRenewalRequest(
					signedReq,
					[][]*x509.Certificate{mockChain},
				).Return(nil, mockErr)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) trustgrpc.ChainBuilder {
				return mock_grpc.NewMockChainBuilder(ctrl)
			},
			Signer: func(ctrl *gomock.Controller) trustgrpc.Signer {
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
		},
		"failed to build chain": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) trustgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyChainRenewalRequest(
					signedReq,
					[][]*x509.Certificate{mockChain},
				).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) trustgrpc.ChainBuilder {
				cb := mock_grpc.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(nil, mockErr)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) trustgrpc.Signer {
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
		},
		"db write error": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) trustgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyChainRenewalRequest(
					signedReq,
					[][]*x509.Certificate{mockChain},
				).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) trustgrpc.ChainBuilder {
				cb := mock_grpc.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(mockIssuedChain, nil)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) trustgrpc.Signer {
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
		},
		"failed to sign": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) trustgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyChainRenewalRequest(
					signedReq,
					[][]*x509.Certificate{mockChain},
				).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) trustgrpc.ChainBuilder {
				cb := mock_grpc.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(mockIssuedChain, nil)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) trustgrpc.Signer {
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
		},
		"valid": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) trustgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyChainRenewalRequest(signedReq,
					[][]*x509.Certificate{mockChain}).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) trustgrpc.ChainBuilder {
				cb := mock_grpc.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(mockIssuedChain, nil)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) trustgrpc.Signer {
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
		},
	}
	for name, tc := range tests {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			s := trustgrpc.RenewalServer{
				Verifier:     tc.Verifier(ctrl),
				ChainBuilder: tc.ChainBuilder(ctrl),
				Signer:       tc.Signer(ctrl),
				DB:           tc.DB(ctrl),
			}
			_, err := s.ChainRenewal(context.Background(), tc.Request(t))
			tc.Assertion(t, err)
			assert.Equal(t, tc.Code, status.Code(err))
		})
	}
}

func genKey(t *testing.T) crypto.Signer {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	return privateKey
}

type chainQueryMatcher struct {
	IA           addr.IA
	SubjectKeyID []byte
}

func (m chainQueryMatcher) Matches(x interface{}) bool {
	v, ok := x.(trust.ChainQuery)
	if !ok {
		return false
	}
	return v.IA.Equal(m.IA) && bytes.Equal(v.SubjectKeyID, m.SubjectKeyID)
}

func (m chainQueryMatcher) String() string {
	return fmt.Sprintf("%+v, %+v", m.IA, m.SubjectKeyID)
}
