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
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/cs/trust/handler"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
)

func TestChainReqHandle(t *testing.T) {
	ia110 := xtest.MustParseIA("1-ff00:0:110")
	skid := []byte("subject_key_id")
	date := time.Now()
	internal := serrors.New("internal")
	dummyChains := [][]*x509.Certificate{{{Raw: []byte("dummy AS")}, {Raw: []byte("dummy CA")}}}

	tests := map[string]struct {
		Request        func(ctrl *gomock.Controller) *infra.Request
		Provider       func(ctrl *gomock.Controller) trust.Provider
		ExpectedResult *infra.HandlerResult
	}{
		"nil request": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				return nil
			},
			Provider: func(ctrl *gomock.Controller) trust.Provider {
				return mock_trust.NewMockProvider(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		"wrong message type": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				return infra.NewRequest(context.Background(), &cert_mgmt.Chain{}, nil, nil, 0)
			},
			Provider: func(ctrl *gomock.Controller) trust.Provider {
				return mock_trust.NewMockProvider(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		"no messenger": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				return infra.NewRequest(context.Background(), &cert_mgmt.ChainReq{}, nil, nil, 0)
			},
			Provider: func(ctrl *gomock.Controller) trust.Provider {
				return mock_trust.NewMockProvider(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		"trustengine error": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				rw.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainReq{
						RawIA:        ia110.IAInt(),
						SubjectKeyID: skid,
						RawDate:      date.Unix(),
					},
					nil, nil, 0,
				)
			},
			Provider: func(ctrl *gomock.Controller) trust.Provider {
				p := mock_trust.NewMockProvider(ctrl)
				p.EXPECT().GetChains(gomock.Any(),
					trust.ChainQuery{
						IA:           ia110,
						SubjectKeyID: skid,
						Date:         date.Truncate(time.Second),
					},
					gomock.Any(), gomock.Any(),
				).Return(nil, internal)
				return p
			},
			ExpectedResult: infra.MetricsErrTrustStore(internal),
		},
		"send error": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				pld := cert_mgmt.NewChain(dummyChains)
				rw.EXPECT().SendCertChainReply(gomock.Any(), pld).Return(infra.ErrTransport)
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainReq{
						RawIA:        ia110.IAInt(),
						SubjectKeyID: skid,
						RawDate:      date.Unix(),
					},
					nil, nil, 0,
				)
			},
			Provider: func(ctrl *gomock.Controller) trust.Provider {
				p := mock_trust.NewMockProvider(ctrl)
				p.EXPECT().GetChains(gomock.Any(),
					trust.ChainQuery{
						IA:           ia110,
						SubjectKeyID: skid,
						Date:         date.Truncate(time.Second),
					},
					gomock.Any(), gomock.Any(),
				).Return(dummyChains, nil)
				return p
			},
			ExpectedResult: infra.MetricsErrMsger(infra.ErrTransport),
		},
		"valid": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				pld := cert_mgmt.NewChain(dummyChains)
				rw.EXPECT().SendCertChainReply(gomock.Any(), pld).Return(nil)
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainReq{
						RawIA:        ia110.IAInt(),
						SubjectKeyID: skid,
						RawDate:      date.Unix(),
					},
					nil, nil, 0,
				)
			},
			Provider: func(ctrl *gomock.Controller) trust.Provider {
				p := mock_trust.NewMockProvider(ctrl)
				p.EXPECT().GetChains(gomock.Any(),
					trust.ChainQuery{
						IA:           ia110,
						SubjectKeyID: skid,
						Date:         date.Truncate(time.Second),
					},
					gomock.Any(), gomock.Any(),
				).Return(dummyChains, nil)
				return p
			},
			ExpectedResult: infra.MetricsResultOk,
		},
	}
	for n, tc := range tests {
		name, test := n, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			h := handler.ChainReq{Provider: test.Provider(ctrl), IA: ia110}
			result := h.Handle(test.Request(ctrl))
			assert.Equal(t, test.ExpectedResult, result)
		})
	}
}
