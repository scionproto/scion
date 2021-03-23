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
	"math/big"
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
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	renewalgrpc "github.com/scionproto/scion/go/pkg/ca/renewal/grpc"
	"github.com/scionproto/scion/go/pkg/ca/renewal/grpc/mock_grpc"
	"github.com/scionproto/scion/go/pkg/ca/renewal/mock_renewal"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
)

var (
	mockErr = serrors.New("send error")
	mockCSR = &x509.CertificateRequest{
		Raw: []byte("mock CSR"),
		Subject: pkix.Name{Names: []pkix.AttributeTypeAndValue{{
			Type:  cppki.OIDNameIA,
			Value: "1-ff00:0:111",
		}}},
	}
	mockChain = []*x509.Certificate{
		{
			Raw:          []byte("mock AS cert"),
			SubjectKeyId: []byte("mock cert subject key"),
		},
		{Raw: []byte("mock CA cert")},
	}
	mockIssuedChain = []*x509.Certificate{
		{Raw: []byte("mock issued AS cert")},
		{Raw: []byte("mock CA cert")},
	}
)

func TestChainRenewalRequestHandleLegacy(t *testing.T) {
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
		},
	}
	for name, tc := range tests {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			s := renewalgrpc.RenewalServer{
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

func TestChainRenewalRequestHandle(t *testing.T) {
	clientKey, chain := genChain(t)
	signedReq, err := renewal.NewChainRenewalRequest(context.Background(), mockCSR.Raw,
		trust.Signer{
			PrivateKey: clientKey,
			Algorithm:  signed.ECDSAWithSHA256,
			ChainValidity: cppki.Validity{
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(time.Hour),
			},
			Expiration:   time.Now().Add(time.Hour - time.Minute),
			IA:           xtest.MustParseIA("1-ff00:0:111"),
			SubjectKeyID: chain[0].SubjectKeyId,
			Chain:        chain,
		},
	)
	require.NoError(t, err)

	tests := map[string]struct {
		Request      func(t *testing.T) *cppb.ChainRenewalRequest
		Verifier     func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier
		ChainBuilder func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder
		CMSSigner    func(ctrl *gomock.Controller) renewalgrpc.CMSSigner
		DB           func(ctrl *gomock.Controller) renewal.DB
		IA           addr.IA
		Assertion    assert.ErrorAssertionFunc
		Code         codes.Code
	}{
		"dummy request": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return &cppb.ChainRenewalRequest{
					CmsSignedRequest: []byte("dummy request"),
				}
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				return mock_grpc.NewMockRenewalRequestVerifier(ctrl)
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				return mock_grpc.NewMockChainBuilder(ctrl)
			},
			CMSSigner: func(ctrl *gomock.Controller) renewalgrpc.CMSSigner {
				return mock_grpc.NewMockCMSSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				return mock_renewal.NewMockDB(ctrl)
			},
			IA:        xtest.MustParseIA("1-ff00:0:110"),
			Assertion: assert.Error,
			Code:      codes.InvalidArgument,
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
			CMSSigner: func(ctrl *gomock.Controller) renewalgrpc.CMSSigner {
				return mock_grpc.NewMockCMSSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				return mock_renewal.NewMockDB(ctrl)
			},
			IA:        xtest.MustParseIA("1-ff00:0:112"),
			Assertion: assert.Error,
			Code:      codes.PermissionDenied,
		},
		"invalid signature": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyCMSSignedRenewalRequest(
					context.Background(),
					signedReq.CmsSignedRequest,
				).Return(nil, mockErr)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				return mock_grpc.NewMockChainBuilder(ctrl)
			},
			CMSSigner: func(ctrl *gomock.Controller) renewalgrpc.CMSSigner {
				return mock_grpc.NewMockCMSSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				return mock_renewal.NewMockDB(ctrl)
			},
			IA:        xtest.MustParseIA("1-ff00:0:110"),
			Assertion: assert.Error,
			Code:      codes.InvalidArgument,
		},
		"failed to build chain": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyCMSSignedRenewalRequest(
					context.Background(),
					signedReq.CmsSignedRequest,
				).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				cb := mock_grpc.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(nil, mockErr)
				return cb
			},
			CMSSigner: func(ctrl *gomock.Controller) renewalgrpc.CMSSigner {
				return mock_grpc.NewMockCMSSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				return mock_renewal.NewMockDB(ctrl)
			},
			IA:        xtest.MustParseIA("1-ff00:0:110"),
			Assertion: assert.Error,
			Code:      codes.Unavailable,
		},
		"db write error": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyCMSSignedRenewalRequest(
					context.Background(),
					signedReq.CmsSignedRequest,
				).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				cb := mock_grpc.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(mockIssuedChain, nil)
				return cb
			},
			CMSSigner: func(ctrl *gomock.Controller) renewalgrpc.CMSSigner {
				return mock_grpc.NewMockCMSSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().InsertClientChain(gomock.Any(), mockIssuedChain).Return(false, mockErr)
				return db
			},
			IA:        xtest.MustParseIA("1-ff00:0:110"),
			Assertion: assert.Error,
			Code:      codes.Unavailable,
		},
		"failed to sign": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyCMSSignedRenewalRequest(
					context.Background(),
					signedReq.CmsSignedRequest,
				).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				cb := mock_grpc.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(mockIssuedChain, nil)
				return cb
			},
			CMSSigner: func(ctrl *gomock.Controller) renewalgrpc.CMSSigner {
				signer := mock_grpc.NewMockCMSSigner(ctrl)
				signer.EXPECT().SignCMS(gomock.Any(), gomock.Any()).Return(nil, mockErr)
				return signer
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().InsertClientChain(gomock.Any(), mockIssuedChain)
				return db
			},
			IA:        xtest.MustParseIA("1-ff00:0:110"),
			Assertion: assert.Error,
			Code:      codes.Unavailable,
		},
		"valid": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			Verifier: func(ctrl *gomock.Controller) renewalgrpc.RenewalRequestVerifier {
				v := mock_grpc.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyCMSSignedRenewalRequest(context.Background(),
					signedReq.CmsSignedRequest).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) renewalgrpc.ChainBuilder {
				cb := mock_grpc.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(mockIssuedChain, nil)
				return cb
			},
			CMSSigner: func(ctrl *gomock.Controller) renewalgrpc.CMSSigner {
				signer := mock_grpc.NewMockCMSSigner(ctrl)
				signer.EXPECT().SignCMS(gomock.Any(), gomock.Any())
				return signer
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().InsertClientChain(gomock.Any(), mockIssuedChain)
				return db
			},
			IA:        xtest.MustParseIA("1-ff00:0:110"),
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
			s := renewalgrpc.RenewalServer{
				Verifier:     tc.Verifier(ctrl),
				ChainBuilder: tc.ChainBuilder(ctrl),
				CMSSigner:    tc.CMSSigner(ctrl),
				DB:           tc.DB(ctrl),
				IA:           tc.IA,
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

func genChain(t *testing.T) (*ecdsa.PrivateKey, []*x509.Certificate) {
	t.Helper()

	caKey, caCert := genCertCA(t, "1-ff00:0:110")
	ca := cppki.CAPolicy{
		Validity:    time.Hour,
		Certificate: caCert,
		Signer:      caKey,
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	chain, err := ca.CreateChain(&x509.CertificateRequest{
		Subject: pkix.Name{Names: []pkix.AttributeTypeAndValue{{
			Type:  cppki.OIDNameIA,
			Value: "1-ff00:0:111",
		}}},
		PublicKey: clientKey.Public(),
	})
	require.NoError(t, err)
	return clientKey, chain
}

func genCertCA(t *testing.T, ia string) (*ecdsa.PrivateKey, *x509.Certificate) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	skid, err := cppki.SubjectKeyID(key.Public())
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{{
			Type:  cppki.OIDNameIA,
			Value: ia,
		}}},
		SerialNumber:          serial,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		SubjectKeyId:          skid,
		AuthorityKeyId:        skid,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	return key, signCert(t, tmpl, tmpl, key.Public(), key)
}

func signCert(
	t *testing.T,
	tmpl, issuer *x509.Certificate,
	subjectKey crypto.PublicKey,
	issuerKey crypto.PrivateKey,
) *x509.Certificate {

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, subjectKey, issuerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(raw)
	require.NoError(t, err)
	return cert
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
