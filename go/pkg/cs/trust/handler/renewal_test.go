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

package handler_test

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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	libctrl "github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg/mock_seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/cs/trust/handler"
	"github.com/scionproto/scion/go/pkg/cs/trust/handler/mock_handler"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
	"github.com/scionproto/scion/go/pkg/trust/renewal/mock_renewal"
	"github.com/scionproto/scion/go/proto"
)

func TestChainRenewalRequestHandle(t *testing.T) {
	mockTime := time.Now()
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
	mockIssuedChain := []*x509.Certificate{
		{Raw: []byte("mock issued AS cert")},
		{Raw: []byte("mock CA cert")},
	}
	tests := map[string]struct {
		Request        func(ctrl *gomock.Controller) *infra.Request
		Verifier       func(ctrl *gomock.Controller) handler.RenewalRequestVerifier
		ChainBuilder   func(ctrl *gomock.Controller) handler.ChainBuilder
		Signer         func(ctrl *gomock.Controller) ctrl.Signer
		DB             func(ctrl *gomock.Controller) renewal.DB
		ExpectedResult *infra.HandlerResult
	}{
		"nil request": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				return nil
			},
			Verifier: func(ctrl *gomock.Controller) handler.RenewalRequestVerifier {
				return mock_handler.NewMockRenewalRequestVerifier(ctrl)
			},
			ChainBuilder: func(ctrl *gomock.Controller) handler.ChainBuilder {
				return mock_handler.NewMockChainBuilder(ctrl)
			},
			Signer: func(ctrl *gomock.Controller) ctrl.Signer {
				return mock_seg.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				return mock_renewal.NewMockDB(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		"wrong message type": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				return infra.NewRequest(context.Background(), &cert_mgmt.Chain{}, nil, nil, 0)
			},
			Verifier: func(ctrl *gomock.Controller) handler.RenewalRequestVerifier {
				return mock_handler.NewMockRenewalRequestVerifier(ctrl)
			},
			ChainBuilder: func(ctrl *gomock.Controller) handler.ChainBuilder {
				return mock_handler.NewMockChainBuilder(ctrl)
			},
			Signer: func(ctrl *gomock.Controller) ctrl.Signer {
				return mock_seg.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				return mock_renewal.NewMockDB(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		"no messenger": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				return infra.NewRequest(context.Background(),
					&cert_mgmt.ChainRenewalRequest{}, nil, nil, 0)
			},
			Verifier: func(ctrl *gomock.Controller) handler.RenewalRequestVerifier {
				return mock_handler.NewMockRenewalRequestVerifier(ctrl)
			},
			ChainBuilder: func(ctrl *gomock.Controller) handler.ChainBuilder {
				return mock_handler.NewMockChainBuilder(ctrl)
			},
			Signer: func(ctrl *gomock.Controller) ctrl.Signer {
				return mock_seg.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				return mock_renewal.NewMockDB(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		"invalid signer src": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				rw.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainRenewalRequest{
						RawCSR: []byte("mock CSR"),
						Signature: &proto.SignS{
							Src: []byte("troll"),
						},
					}, nil, nil, 0)
			},
			Verifier: func(ctrl *gomock.Controller) handler.RenewalRequestVerifier {
				return mock_handler.NewMockRenewalRequestVerifier(ctrl)
			},
			ChainBuilder: func(ctrl *gomock.Controller) handler.ChainBuilder {
				return mock_handler.NewMockChainBuilder(ctrl)
			},
			Signer: func(ctrl *gomock.Controller) ctrl.Signer {
				return mock_seg.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				return mock_renewal.NewMockDB(ctrl)
			},
			ExpectedResult: infra.MetricsErrInvalid,
		},
		"db read error": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				rw.EXPECT().SendAckReply(gomock.Any(), &ack.Ack{
					Err:     proto.Ack_ErrCode_retry,
					ErrDesc: "db error",
				})
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainRenewalRequest{
						RawCSR: mockCSR.Raw,
						Signature: &proto.SignS{
							Timestamp: util.TimeToSecs(mockTime),
							Src: libctrl.X509SignSrc{
								IA:           xtest.MustParseIA("1-ff00:0:111"),
								Base:         1,
								Serial:       1,
								SubjectKeyID: mockChain[0].SubjectKeyId,
							}.Pack(),
						},
					}, nil, nil, 0)
			},
			Verifier: func(ctrl *gomock.Controller) handler.RenewalRequestVerifier {
				v := mock_handler.NewMockRenewalRequestVerifier(ctrl)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) handler.ChainBuilder {
				cb := mock_handler.NewMockChainBuilder(ctrl)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) ctrl.Signer {
				return mock_seg.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().ClientChains(gomock.Any(), chainQueryMatcher{
					IA:           xtest.MustParseIA("1-ff00:0:111"),
					SubjectKeyID: mockChain[0].SubjectKeyId,
				}).Return(nil, mockErr)
				return db
			},
			ExpectedResult: infra.MetricsErrTrustDB(mockErr),
		},
		"not client": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				rw.EXPECT().SendAckReply(gomock.Any(), &ack.Ack{
					Err:     proto.Ack_ErrCode_reject,
					ErrDesc: "not client",
				})
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainRenewalRequest{
						RawCSR: mockCSR.Raw,
						Signature: &proto.SignS{
							Timestamp: util.TimeToSecs(mockTime),
							Src: libctrl.X509SignSrc{
								IA:           xtest.MustParseIA("1-ff00:0:111"),
								Base:         1,
								Serial:       1,
								SubjectKeyID: mockChain[0].SubjectKeyId,
							}.Pack(),
						},
					}, nil, nil, 0)
			},
			Verifier: func(ctrl *gomock.Controller) handler.RenewalRequestVerifier {
				v := mock_handler.NewMockRenewalRequestVerifier(ctrl)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) handler.ChainBuilder {
				cb := mock_handler.NewMockChainBuilder(ctrl)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) ctrl.Signer {
				return mock_seg.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().ClientChains(gomock.Any(), chainQueryMatcher{
					IA:           xtest.MustParseIA("1-ff00:0:111"),
					SubjectKeyID: mockChain[0].SubjectKeyId,
				}).Return(nil, nil)
				return db
			},
			ExpectedResult: infra.MetricsErrInvalid,
		},
		"invalid signature": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				rw.EXPECT().SendAckReply(gomock.Any(), &ack.Ack{
					Err:     proto.Ack_ErrCode_reject,
					ErrDesc: "invalid request",
				})
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainRenewalRequest{
						RawCSR: mockCSR.Raw,
						Signature: &proto.SignS{
							Timestamp: util.TimeToSecs(mockTime),
							Src: libctrl.X509SignSrc{
								IA:           xtest.MustParseIA("1-ff00:0:111"),
								Base:         1,
								Serial:       1,
								SubjectKeyID: mockChain[0].SubjectKeyId,
							}.Pack(),
						},
					}, nil, nil, 0)
			},
			Verifier: func(ctrl *gomock.Controller) handler.RenewalRequestVerifier {
				v := mock_handler.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyChainRenewalRequest(&cert_mgmt.ChainRenewalRequest{
					RawCSR: mockCSR.Raw,
					Signature: &proto.SignS{
						Timestamp: util.TimeToSecs(mockTime),
						Src: libctrl.X509SignSrc{
							IA:           xtest.MustParseIA("1-ff00:0:111"),
							Base:         1,
							Serial:       1,
							SubjectKeyID: mockChain[0].SubjectKeyId,
						}.Pack(),
					},
				}, [][]*x509.Certificate{mockChain}).Return(nil, mockErr)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) handler.ChainBuilder {
				cb := mock_handler.NewMockChainBuilder(ctrl)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) ctrl.Signer {
				return mock_seg.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().ClientChains(gomock.Any(), chainQueryMatcher{
					IA:           xtest.MustParseIA("1-ff00:0:111"),
					SubjectKeyID: mockChain[0].SubjectKeyId,
				}).Return([][]*x509.Certificate{mockChain}, nil)
				return db
			},
			ExpectedResult: infra.MetricsErrInvalid,
		},
		"failed to build chain": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				rw.EXPECT().SendAckReply(gomock.Any(), &ack.Ack{
					Err:     proto.Ack_ErrCode_retry,
					ErrDesc: "failed to sign",
				})
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainRenewalRequest{
						RawCSR: mockCSR.Raw,
						Signature: &proto.SignS{
							Timestamp: util.TimeToSecs(mockTime),
							Src: libctrl.X509SignSrc{
								IA:           xtest.MustParseIA("1-ff00:0:111"),
								Base:         1,
								Serial:       1,
								SubjectKeyID: mockChain[0].SubjectKeyId,
							}.Pack(),
						},
					}, nil, nil, 0)
			},
			Verifier: func(ctrl *gomock.Controller) handler.RenewalRequestVerifier {
				v := mock_handler.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyChainRenewalRequest(&cert_mgmt.ChainRenewalRequest{
					RawCSR: mockCSR.Raw,
					Signature: &proto.SignS{
						Timestamp: util.TimeToSecs(mockTime),
						Src: libctrl.X509SignSrc{
							IA:           xtest.MustParseIA("1-ff00:0:111"),
							Base:         1,
							Serial:       1,
							SubjectKeyID: mockChain[0].SubjectKeyId,
						}.Pack(),
					},
				}, [][]*x509.Certificate{mockChain}).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) handler.ChainBuilder {
				cb := mock_handler.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(nil, mockErr)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) ctrl.Signer {
				return mock_seg.NewMockSigner(ctrl)
			},
			DB: func(ctrl *gomock.Controller) renewal.DB {
				db := mock_renewal.NewMockDB(ctrl)
				db.EXPECT().ClientChains(gomock.Any(), chainQueryMatcher{
					IA:           xtest.MustParseIA("1-ff00:0:111"),
					SubjectKeyID: mockChain[0].SubjectKeyId,
				}).Return([][]*x509.Certificate{mockChain}, nil)
				return db
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		"failed to sign": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				rw.EXPECT().SendAckReply(gomock.Any(), &ack.Ack{
					Err:     proto.Ack_ErrCode_reject,
					ErrDesc: "signer error",
				})
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainRenewalRequest{
						RawCSR: mockCSR.Raw,
						Signature: &proto.SignS{
							Timestamp: util.TimeToSecs(mockTime),
							Src: libctrl.X509SignSrc{
								IA:           xtest.MustParseIA("1-ff00:0:111"),
								Base:         1,
								Serial:       1,
								SubjectKeyID: mockChain[0].SubjectKeyId,
							}.Pack(),
						},
					}, nil, nil, 0)
			},
			Verifier: func(ctrl *gomock.Controller) handler.RenewalRequestVerifier {
				v := mock_handler.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyChainRenewalRequest(&cert_mgmt.ChainRenewalRequest{
					RawCSR: mockCSR.Raw,
					Signature: &proto.SignS{
						Timestamp: util.TimeToSecs(mockTime),
						Src: libctrl.X509SignSrc{
							IA:           xtest.MustParseIA("1-ff00:0:111"),
							Base:         1,
							Serial:       1,
							SubjectKeyID: mockChain[0].SubjectKeyId,
						}.Pack(),
					},
				}, [][]*x509.Certificate{mockChain}).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) handler.ChainBuilder {
				cb := mock_handler.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(mockIssuedChain, nil)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) ctrl.Signer {
				signer := mock_seg.NewMockSigner(ctrl)
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
			ExpectedResult: infra.MetricsErrInternal,
		},
		"db write error": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				rw.EXPECT().SendAckReply(gomock.Any(), &ack.Ack{
					Err:     proto.Ack_ErrCode_retry,
					ErrDesc: "db error",
				})
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainRenewalRequest{
						RawCSR: mockCSR.Raw,
						Signature: &proto.SignS{
							Timestamp: util.TimeToSecs(mockTime),
							Src: libctrl.X509SignSrc{
								IA:           xtest.MustParseIA("1-ff00:0:111"),
								Base:         1,
								Serial:       1,
								SubjectKeyID: mockChain[0].SubjectKeyId,
							}.Pack(),
						},
					}, nil, nil, 0)
			},
			Verifier: func(ctrl *gomock.Controller) handler.RenewalRequestVerifier {
				v := mock_handler.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyChainRenewalRequest(&cert_mgmt.ChainRenewalRequest{
					RawCSR: mockCSR.Raw,
					Signature: &proto.SignS{
						Timestamp: util.TimeToSecs(mockTime),
						Src: libctrl.X509SignSrc{
							IA:           xtest.MustParseIA("1-ff00:0:111"),
							Base:         1,
							Serial:       1,
							SubjectKeyID: mockChain[0].SubjectKeyId,
						}.Pack(),
					},
				}, [][]*x509.Certificate{mockChain}).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) handler.ChainBuilder {
				cb := mock_handler.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(mockIssuedChain, nil)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) ctrl.Signer {
				return mock_seg.NewMockSigner(ctrl)
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
			ExpectedResult: infra.MetricsErrTrustDB(mockErr),
		},
		"send error": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				rw.EXPECT().SendChainRenewalReply(gomock.Any(), gomock.Any()).
					Return(mockErr)
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainRenewalRequest{
						RawCSR: mockCSR.Raw,
						Signature: &proto.SignS{
							Timestamp: util.TimeToSecs(mockTime),
							Src: libctrl.X509SignSrc{
								IA:           xtest.MustParseIA("1-ff00:0:111"),
								Base:         1,
								Serial:       1,
								SubjectKeyID: mockChain[0].SubjectKeyId,
							}.Pack(),
						},
					}, nil, nil, 0)
			},
			Verifier: func(ctrl *gomock.Controller) handler.RenewalRequestVerifier {
				v := mock_handler.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyChainRenewalRequest(&cert_mgmt.ChainRenewalRequest{
					RawCSR: mockCSR.Raw,
					Signature: &proto.SignS{
						Timestamp: util.TimeToSecs(mockTime),
						Src: libctrl.X509SignSrc{
							IA:           xtest.MustParseIA("1-ff00:0:111"),
							Base:         1,
							Serial:       1,
							SubjectKeyID: mockChain[0].SubjectKeyId,
						}.Pack(),
					},
				}, [][]*x509.Certificate{mockChain}).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) handler.ChainBuilder {
				cb := mock_handler.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(mockIssuedChain, nil)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) ctrl.Signer {
				signer := mock_seg.NewMockSigner(ctrl)
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
			ExpectedResult: infra.MetricsErrMsger(mockErr),
		},
		"valid": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				rw.EXPECT().SendChainRenewalReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainRenewalRequest{
						RawCSR: mockCSR.Raw,
						Signature: &proto.SignS{
							Timestamp: util.TimeToSecs(mockTime),
							Src: libctrl.X509SignSrc{
								IA:           xtest.MustParseIA("1-ff00:0:111"),
								Base:         1,
								Serial:       1,
								SubjectKeyID: mockChain[0].SubjectKeyId,
							}.Pack(),
						},
					}, nil, nil, 0)
			},
			Verifier: func(ctrl *gomock.Controller) handler.RenewalRequestVerifier {
				v := mock_handler.NewMockRenewalRequestVerifier(ctrl)
				v.EXPECT().VerifyChainRenewalRequest(&cert_mgmt.ChainRenewalRequest{
					RawCSR: mockCSR.Raw,
					Signature: &proto.SignS{
						Timestamp: util.TimeToSecs(mockTime),
						Src: libctrl.X509SignSrc{
							IA:           xtest.MustParseIA("1-ff00:0:111"),
							Base:         1,
							Serial:       1,
							SubjectKeyID: mockChain[0].SubjectKeyId,
						}.Pack(),
					},
				}, [][]*x509.Certificate{mockChain}).Return(mockCSR, nil)
				return v
			},
			ChainBuilder: func(ctrl *gomock.Controller) handler.ChainBuilder {
				cb := mock_handler.NewMockChainBuilder(ctrl)
				cb.EXPECT().CreateChain(gomock.Any(), gomock.Any()).Return(mockIssuedChain, nil)
				return cb
			},
			Signer: func(ctrl *gomock.Controller) ctrl.Signer {
				signer := mock_seg.NewMockSigner(ctrl)
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
			ExpectedResult: infra.MetricsResultOk,
		},
	}
	for name, tc := range tests {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			h := handler.ChainRenewalRequest{
				Verifier:     tc.Verifier(ctrl),
				ChainBuilder: tc.ChainBuilder(ctrl),
				Signer:       tc.Signer(ctrl),
				DB:           tc.DB(ctrl),
			}
			result := h.Handle(tc.Request(ctrl))
			assert.Equal(t, tc.ExpectedResult, result)
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
