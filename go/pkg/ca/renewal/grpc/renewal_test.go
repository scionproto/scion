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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	"github.com/scionproto/scion/go/pkg/ca/renewal/grpc"
	renewalgrpc "github.com/scionproto/scion/go/pkg/ca/renewal/grpc"
	"github.com/scionproto/scion/go/pkg/ca/renewal/grpc/mock_grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
)

func TestRenewalServerChainRenewal(t *testing.T) {
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
		request       func(t *testing.T) *cppb.ChainRenewalRequest
		legacyHandler func(ctrl *gomock.Controller) grpc.LegacyRequestHandler
		cmsHandler    func(ctrl *gomock.Controller) grpc.CMSRequestHandler
		cmsSigner     func(ctrl *gomock.Controller) grpc.CMSSigner
		metric        string
		assertion     assert.ErrorAssertionFunc
	}{
		"legacy not configured": {
			request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return &cppb.ChainRenewalRequest{
					SignedRequest: signedReq.SignedRequest,
				}
			},
			legacyHandler: func(ctrl *gomock.Controller) grpc.LegacyRequestHandler {
				return nil
			},
			cmsHandler: func(ctrl *gomock.Controller) grpc.CMSRequestHandler {
				r := mock_grpc.NewMockCMSRequestHandler(ctrl)
				return r
			},
			cmsSigner: func(ctrl *gomock.Controller) renewalgrpc.CMSSigner {
				return mock_grpc.NewMockCMSSigner(ctrl)
			},
			assertion: assert.Error,
			metric:    "err_backend",
		},
		"legacy success": {
			request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return &cppb.ChainRenewalRequest{}
			},
			legacyHandler: func(ctrl *gomock.Controller) grpc.LegacyRequestHandler {
				r := mock_grpc.NewMockLegacyRequestHandler(ctrl)
				r.EXPECT().HandleLegacyRequest(
					gomock.Any(), gomock.Any(),
				).Return(&cppb.ChainRenewalResponse{}, nil)
				return r
			},
			cmsHandler: func(ctrl *gomock.Controller) grpc.CMSRequestHandler {
				r := mock_grpc.NewMockCMSRequestHandler(ctrl)
				return r
			},
			cmsSigner: func(ctrl *gomock.Controller) renewalgrpc.CMSSigner {
				return mock_grpc.NewMockCMSSigner(ctrl)
			},
			assertion: assert.NoError,
			metric:    "ok_success",
		},
		"legacy error": {
			request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return &cppb.ChainRenewalRequest{}
			},
			legacyHandler: func(ctrl *gomock.Controller) grpc.LegacyRequestHandler {
				r := mock_grpc.NewMockLegacyRequestHandler(ctrl)
				r.EXPECT().HandleLegacyRequest(
					gomock.Any(), gomock.Any(),
				).Return(nil, fmt.Errorf("dummy"))
				return r
			},
			cmsHandler: func(ctrl *gomock.Controller) grpc.CMSRequestHandler {
				r := mock_grpc.NewMockCMSRequestHandler(ctrl)
				return r
			},
			cmsSigner: func(ctrl *gomock.Controller) renewalgrpc.CMSSigner {
				return mock_grpc.NewMockCMSSigner(ctrl)
			},
			assertion: assert.Error,
			metric:    "err_backend",
		},
		"CMS": {
			request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			legacyHandler: func(ctrl *gomock.Controller) grpc.LegacyRequestHandler {
				r := mock_grpc.NewMockLegacyRequestHandler(ctrl)
				return r
			},
			cmsHandler: func(ctrl *gomock.Controller) grpc.CMSRequestHandler {
				r := mock_grpc.NewMockCMSRequestHandler(ctrl)
				r.EXPECT().HandleCMSRequest(
					gomock.Any(), gomock.Any(),
				).Return(mockChain, nil)
				return r
			},
			cmsSigner: func(ctrl *gomock.Controller) renewalgrpc.CMSSigner {
				signer := mock_grpc.NewMockCMSSigner(ctrl)
				signer.EXPECT().SignCMS(gomock.Any(), gomock.Any())
				return signer
			},
			assertion: assert.NoError,
			metric:    "ok_success",
		},
		"CMS sign error": {
			request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return signedReq
			},
			legacyHandler: func(ctrl *gomock.Controller) grpc.LegacyRequestHandler {
				r := mock_grpc.NewMockLegacyRequestHandler(ctrl)
				return r
			},
			cmsHandler: func(ctrl *gomock.Controller) grpc.CMSRequestHandler {
				r := mock_grpc.NewMockCMSRequestHandler(ctrl)
				r.EXPECT().HandleCMSRequest(
					gomock.Any(), gomock.Any(),
				).Return(mockChain, nil)
				return r
			},
			cmsSigner: func(ctrl *gomock.Controller) renewalgrpc.CMSSigner {
				signer := mock_grpc.NewMockCMSSigner(ctrl)
				signer.EXPECT().SignCMS(gomock.Any(), gomock.Any()).Return(nil, mockErr)
				return signer
			},
			assertion: assert.Error,
			metric:    "err_backend",
		},

		"CMS error": {
			request: func(t *testing.T) *cppb.ChainRenewalRequest {
				return &cppb.ChainRenewalRequest{
					CmsSignedRequest: []byte("dummy request"),
				}
			},
			legacyHandler: func(ctrl *gomock.Controller) grpc.LegacyRequestHandler {
				r := mock_grpc.NewMockLegacyRequestHandler(ctrl)
				return r
			},
			cmsHandler: func(ctrl *gomock.Controller) grpc.CMSRequestHandler {
				r := mock_grpc.NewMockCMSRequestHandler(ctrl)
				r.EXPECT().HandleCMSRequest(
					gomock.Any(), gomock.Any(),
				).Return(nil, fmt.Errorf("dummy"))
				return r
			},
			cmsSigner: func(ctrl *gomock.Controller) renewalgrpc.CMSSigner {
				return mock_grpc.NewMockCMSSigner(ctrl)
			},
			assertion: assert.Error,
			metric:    "err_backend",
		},
	}

	for name, tc := range tests {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			ctr := metrics.NewTestCounter()
			defer ctrl.Finish()
			s := &grpc.RenewalServer{
				LegacyHandler: tc.legacyHandler(ctrl),
				CMSHandler:    tc.cmsHandler(ctrl),
				CMSSigner:     tc.cmsSigner(ctrl),
				Metrics: renewalgrpc.RenewalServerMetrics{
					BackendErrors: ctr.With("test_tag", "err_backend"),
					Success:       ctr.With("test_tag", "ok_success"),
				},
			}
			_, err := s.ChainRenewal(context.Background(), tc.request(t))
			tc.assertion(t, err)
			for _, res := range []string{
				"err_backend",
				"ok_success",
			} {
				expected := float64(0)
				if res == tc.metric {
					expected = 1
				}
				assert.Equal(t, expected, metrics.CounterValue(ctr.With("test_tag", res)), res)
			}

		})
	}
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
