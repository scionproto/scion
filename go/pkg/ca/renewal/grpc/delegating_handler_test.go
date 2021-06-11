// Copyright 2021 Anapaya Systems
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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
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
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/ca/api"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	renewalgrpc "github.com/scionproto/scion/go/pkg/ca/renewal/grpc"
	"github.com/scionproto/scion/go/pkg/ca/renewal/grpc/mock_grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
)

func TestDelegatingHandler(t *testing.T) {
	clientKey, chain := genChain(t)
	signer := trust.Signer{
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
	}
	dummyReq, err := renewal.NewChainRenewalRequest(context.Background(), []byte("dummy"), signer)
	require.NoError(t, err)

	type TestCase struct {
		Request       func(t *testing.T) *cppb.ChainRenewalRequest
		Client        func(t *testing.T, ctrl *gomock.Controller) renewalgrpc.CAServiceClient
		Chain         []*x509.Certificate
		Metric        string
		ErrAssertion  assert.ErrorAssertionFunc
		ExpectedError error
	}

	testCases := map[string]TestCase{
		"malformed request": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return &cppb.ChainRenewalRequest{
					CmsSignedRequest: []byte("dummy request"),
				}
			},
			Client: func(t *testing.T, ctrl *gomock.Controller) renewalgrpc.CAServiceClient {
				return mock_grpc.NewMockCAServiceClient(ctrl)
			},
			Metric:       "err_bad_request",
			ErrAssertion: assert.Error,
		},
		"subject without ISD-AS": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				caKey, caCert := genCertCA(t, "1-ff00:0:110")

				serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
				require.NoError(t, err)
				tmpl := &x509.Certificate{
					Subject:      pkix.Name{CommonName: "hermes"},
					SerialNumber: serial,
				}
				cert := signCert(t, tmpl, caCert, clientKey.Public(), caKey)
				s := signer
				s.Chain = []*x509.Certificate{cert, chain[1]}
				req, err := renewal.NewChainRenewalRequest(context.Background(), []byte("dummy"), s)
				require.NoError(t, err)
				return req
			},
			Client: func(t *testing.T, ctrl *gomock.Controller) renewalgrpc.CAServiceClient {
				return mock_grpc.NewMockCAServiceClient(ctrl)
			},
			Metric:       "err_bad_request",
			ErrAssertion: assert.Error,
		},
		"request fails": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return dummyReq
			},
			Client: func(t *testing.T, ctrl *gomock.Controller) renewalgrpc.CAServiceClient {
				c := mock_grpc.NewMockCAServiceClient(ctrl)
				c.EXPECT().PostCertificateRenewal(
					gomock.Any(), 1, api.AS("ff00:0:111"), gomock.Any(),
				).Return(nil, serrors.New("http request failed"))
				return c
			},
			Metric:       "err_internal",
			ErrAssertion: assert.Error,
		},
		"malformed response json": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return dummyReq
			},
			Client: func(t *testing.T, ctrl *gomock.Controller) renewalgrpc.CAServiceClient {
				rr := httptest.NewRecorder()
				rr.WriteHeader(http.StatusOK)
				fmt.Fprint(rr, `{"`)

				c := mock_grpc.NewMockCAServiceClient(ctrl)
				c.EXPECT().PostCertificateRenewal(
					gomock.Any(), 1, api.AS("ff00:0:111"), gomock.Any(),
				).Return(rr.Result(), nil)

				return c
			},
			Metric:       "err_internal",
			ErrAssertion: assert.Error,
		},
		"malformed response content": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return dummyReq
			},
			Client: func(t *testing.T, ctrl *gomock.Controller) renewalgrpc.CAServiceClient {
				rr := httptest.NewRecorder()
				rr.WriteHeader(http.StatusOK)
				fmt.Fprint(rr, `{"certificate_chain":"ZHVtbXk="}`)

				c := mock_grpc.NewMockCAServiceClient(ctrl)
				c.EXPECT().PostCertificateRenewal(
					gomock.Any(), 1, api.AS("ff00:0:111"), gomock.Any(),
				).Return(rr.Result(), nil)

				return c
			},
			Metric:       "err_internal",
			ErrAssertion: assert.Error,
		},
		"success": {
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return dummyReq
			},
			Client: func(t *testing.T, ctrl *gomock.Controller) renewalgrpc.CAServiceClient {
				rep, err := json.Marshal(api.RenewalResponse{
					CertificateChain: api.CertificateChain{
						AsCertificate: chain[0].Raw,
						CaCertificate: chain[1].Raw,
					},
				})
				require.NoError(t, err)

				rr := httptest.NewRecorder()
				http.Error(rr, string(rep), http.StatusOK)

				c := mock_grpc.NewMockCAServiceClient(ctrl)
				c.EXPECT().PostCertificateRenewal(
					gomock.Any(), 1, api.AS("ff00:0:111"), gomock.Any(),
				).Return(rr.Result(), nil)

				return c
			},
			Chain:        chain,
			Metric:       "ok_success",
			ErrAssertion: assert.NoError,
		},
	}

	// Add backend error cases.
	backendErrors := map[string]struct {
		Code          int
		Body          string
		Metric        string
		ExpectedError error
	}{
		"malformed": {
			Code:          http.StatusBadRequest,
			Body:          `{`,
			Metric:        "err_internal",
			ExpectedError: status.Error(codes.Internal, "invalid service response"),
		},
		"unknown": {
			Code:          http.StatusTeapot,
			Body:          `{}`,
			Metric:        "err_internal",
			ExpectedError: status.Error(codes.Internal, "unhandled service response"),
		},
		"BadRequest": {
			Code:          http.StatusBadRequest,
			Body:          `{}`,
			Metric:        "err_bad_request",
			ExpectedError: status.Error(codes.InvalidArgument, "malformed request"),
		},
		"BadRequestWithDetail": {
			Code:          http.StatusBadRequest,
			Body:          `{"detail": "detail"}`,
			Metric:        "err_bad_request",
			ExpectedError: status.Error(codes.InvalidArgument, "malformed request: detail"),
		},
		"Unauthorized": {
			Code:          http.StatusUnauthorized,
			Body:          `{}`,
			Metric:        "err_unavailable",
			ExpectedError: status.Error(codes.Unavailable, "service unavailable"),
		},
		"UnauthorizedWithDetail": {
			Code:   http.StatusUnauthorized,
			Body:   `{"detail": "detail"}`,
			Metric: "err_unavailable",
			// Check internal detail is not leaked.
			ExpectedError: status.Error(codes.Unavailable, "service unavailable"),
		},
		"NotFound": {
			Code:          http.StatusNotFound,
			Body:          `{}`,
			Metric:        "err_bad_request",
			ExpectedError: status.Error(codes.NotFound, "resource not found"),
		},
		"NotFoundWithDetail": {
			Code:          http.StatusNotFound,
			Body:          `{"detail": "detail"}`,
			Metric:        "err_bad_request",
			ExpectedError: status.Error(codes.NotFound, "resource not found: detail"),
		},
		"InternalServerError": {
			Code:          http.StatusInternalServerError,
			Body:          `{}`,
			Metric:        "err_internal",
			ExpectedError: status.Error(codes.Internal, "internal error"),
		},
		"InternalServerErrorWithDetail": {
			Code:   http.StatusInternalServerError,
			Body:   `{"detail": "detail"}`,
			Metric: "err_internal",
			// Check internal detail is not leaked.
			ExpectedError: status.Error(codes.Internal, "internal error"),
		},
		"ServiceUnavailable": {
			Code:          http.StatusServiceUnavailable,
			Body:          `{}`,
			Metric:        "err_unavailable",
			ExpectedError: status.Error(codes.Unavailable, "service unavailable"),
		},
		"ServiceUnavailableWithDetail": {
			Code:          http.StatusServiceUnavailable,
			Body:          `{"detail": "detail"}`,
			Metric:        "err_unavailable",
			ExpectedError: status.Error(codes.Unavailable, "service unavailable: detail"),
		},
	}
	for name, be := range backendErrors {
		name, be := name, be
		testCases["backend "+name] = TestCase{
			Request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return dummyReq
			},
			Client: func(t *testing.T, ctrl *gomock.Controller) renewalgrpc.CAServiceClient {
				rr := httptest.NewRecorder()
				http.Error(rr, be.Body, be.Code)

				c := mock_grpc.NewMockCAServiceClient(ctrl)
				c.EXPECT().PostCertificateRenewal(
					gomock.Any(), 1, api.AS("ff00:0:111"), gomock.Any(),
				).Return(rr.Result(), nil)

				return c
			},
			Metric:        be.Metric,
			ErrAssertion:  assert.Error,
			ExpectedError: be.ExpectedError,
		}

	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			ctr := metrics.NewTestCounter()
			h := renewalgrpc.DelegatingHandler{
				Client: tc.Client(t, ctrl),
				Metrics: renewalgrpc.DelegatingHandlerMetrics{
					BadRequests:   ctr.With("result", "err_bad_request"),
					InternalError: ctr.With("result", "err_internal"),
					Unavailable:   ctr.With("result", "err_unavailable"),
					Success:       ctr.With("result", "ok_success"),
				},
			}
			chain, err := h.HandleCMSRequest(
				context.Background(),
				tc.Request(t),
			)
			tc.ErrAssertion(t, err)
			assert.Equal(t, tc.Chain, chain)

			if tc.ExpectedError != nil {
				assert.Equal(t, tc.ExpectedError, err)
			}

			for _, res := range []string{
				"err_bad_request",
				"err_internal",
				"err_unavailable",
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
