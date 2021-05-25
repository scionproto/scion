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
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	"github.com/scionproto/scion/go/pkg/ca/renewal/grpc"
	renewalgrpc "github.com/scionproto/scion/go/pkg/ca/renewal/grpc"
	"github.com/scionproto/scion/go/pkg/ca/renewal/grpc/mock_grpc"
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

func TestCMSHandleCMSRequest(t *testing.T) {
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
		IA           addr.IA
		Metric       string
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
			IA:        xtest.MustParseIA("1-ff00:0:110"),
			Assertion: assert.Error,
			Code:      codes.InvalidArgument,
			Metric:    "err_parse",
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
			IA:        xtest.MustParseIA("2-ff00:0:112"),
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
			IA:        xtest.MustParseIA("1-ff00:0:110"),
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
			IA:        xtest.MustParseIA("1-ff00:0:110"),
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
			IA:        xtest.MustParseIA("1-ff00:0:110"),
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
			s := &renewalgrpc.CMS{
				Verifier:     tc.Verifier(ctrl),
				ChainBuilder: tc.ChainBuilder(ctrl),
				IA:           tc.IA,
				Metrics: grpc.CMSHandlerMetrics{
					DatabaseError: ctr.With("result", "err_database"),
					InternalError: ctr.With("result", "err_internal"),
					NotFoundError: ctr.With("result", "err_notfound"),
					ParseError:    ctr.With("result", "err_parse"),
					VerifyError:   ctr.With("result", "err_verify"),
					Success:       ctr.With("result", "ok_success"),
				},
			}
			_, err := s.HandleCMSRequest(context.Background(), tc.Request(t))
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
