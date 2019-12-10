// Copyright 2019 Anapaya Systems
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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/mock_v2"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestChainReqHandler(t *testing.T) {
	tests := map[string]struct {
		Request        func(ctrl *gomock.Controller) *infra.Request
		Provider       func(ctrl *gomock.Controller) trust.CryptoProvider
		ExpectedResult *infra.HandlerResult
	}{
		"nil request": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				return nil
			},
			Provider: func(ctrl *gomock.Controller) trust.CryptoProvider {
				return mock_v2.NewMockCryptoProvider(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		"wrong message type": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				return &infra.Request{Message: &cert_mgmt.Chain{}}
			},
			Provider: func(ctrl *gomock.Controller) trust.CryptoProvider {
				return mock_v2.NewMockCryptoProvider(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		"no messenger": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				return &infra.Request{Message: &cert_mgmt.ChainReq{}}
			},
			Provider: func(ctrl *gomock.Controller) trust.CryptoProvider {
				return mock_v2.NewMockCryptoProvider(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		"trust store error": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				rw.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainReq{RawIA: ia110.IAInt(), Version: scrypto.LatestVer},
					nil, nil, 0,
				)
			},
			Provider: func(ctrl *gomock.Controller) trust.CryptoProvider {
				opts := infra.ChainOpts{
					TrustStoreOpts: infra.TrustStoreOpts{
						LocalOnly: false,
					},
					AllowInactiveTRC: true,
				}
				p := mock_v2.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.LatestVer,
					opts, nil).Return(nil, trust.ErrNotFound)
				return p
			},
			ExpectedResult: infra.MetricsErrTrustStore(trust.ErrNotFound),
		},
		"send error": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				pld := &cert_mgmt.Chain{RawChain: []byte("test")}
				rw.EXPECT().SendCertChainReply(gomock.Any(), pld).Return(infra.ErrTransport)
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainReq{RawIA: ia110.IAInt(), Version: scrypto.LatestVer},
					nil, nil, 0,
				)
			},
			Provider: func(ctrl *gomock.Controller) trust.CryptoProvider {
				opts := infra.ChainOpts{
					TrustStoreOpts: infra.TrustStoreOpts{
						LocalOnly: false,
					},
					AllowInactiveTRC: true,
				}
				p := mock_v2.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.LatestVer,
					opts, nil).Return([]byte("test"), nil)
				return p
			},
			ExpectedResult: infra.MetricsErrMsger(infra.ErrTransport),
		},
		"valid": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				pld := &cert_mgmt.Chain{RawChain: []byte("test")}
				rw.EXPECT().SendCertChainReply(gomock.Any(), pld).Return(nil)
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.ChainReq{RawIA: ia110.IAInt(), Version: scrypto.LatestVer},
					nil, nil, 0,
				)
			},
			Provider: func(ctrl *gomock.Controller) trust.CryptoProvider {
				opts := infra.ChainOpts{
					TrustStoreOpts: infra.TrustStoreOpts{
						LocalOnly: false,
					},
					AllowInactiveTRC: true,
				}
				p := mock_v2.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawChain(gomock.Any(), ia110, scrypto.LatestVer,
					opts, nil).Return([]byte("test"), nil)
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
			handler := trust.NewChainReqHandler(
				test.Request(ctrl),
				test.Provider(ctrl),
			)
			result := handler.Handle()
			assert.Equal(t, test.ExpectedResult, result)
		})
	}
}

func TestTRCReqHandler(t *testing.T) {
	tests := map[string]struct {
		Request        func(ctrl *gomock.Controller) *infra.Request
		Provider       func(ctrl *gomock.Controller) trust.CryptoProvider
		ExpectedResult *infra.HandlerResult
	}{
		"nil request": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				return nil
			},
			Provider: func(ctrl *gomock.Controller) trust.CryptoProvider {
				return mock_v2.NewMockCryptoProvider(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		"wrong message type": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				return &infra.Request{Message: &cert_mgmt.TRC{}}
			},
			Provider: func(ctrl *gomock.Controller) trust.CryptoProvider {
				return mock_v2.NewMockCryptoProvider(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		"no messenger": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				return &infra.Request{Message: &cert_mgmt.TRCReq{}}
			},
			Provider: func(ctrl *gomock.Controller) trust.CryptoProvider {
				return mock_v2.NewMockCryptoProvider(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		"trust store error": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				rw.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.TRCReq{ISD: 1, Version: scrypto.LatestVer},
					nil, nil, 0,
				)
			},
			Provider: func(ctrl *gomock.Controller) trust.CryptoProvider {
				opts := infra.TRCOpts{
					TrustStoreOpts: infra.TrustStoreOpts{
						LocalOnly: false,
					},
					AllowInactive: true,
				}
				p := mock_v2.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawTRC(gomock.Any(), addr.ISD(1), scrypto.LatestVer,
					opts, nil).Return(nil, trust.ErrNotFound)
				return p
			},
			ExpectedResult: infra.MetricsErrTrustStore(trust.ErrNotFound),
		},
		"send error": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				pld := &cert_mgmt.TRC{RawTRC: []byte("test")}
				rw.EXPECT().SendTRCReply(gomock.Any(), pld).Return(infra.ErrTransport)
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.TRCReq{ISD: 1, Version: scrypto.LatestVer},
					nil, nil, 0,
				)
			},
			Provider: func(ctrl *gomock.Controller) trust.CryptoProvider {
				opts := infra.TRCOpts{
					TrustStoreOpts: infra.TrustStoreOpts{
						LocalOnly: false,
					},
					AllowInactive: true,
				}
				p := mock_v2.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawTRC(gomock.Any(), addr.ISD(1), scrypto.LatestVer,
					opts, nil).Return([]byte("test"), nil)
				return p
			},
			ExpectedResult: infra.MetricsErrMsger(infra.ErrTransport),
		},
		"valid": {
			Request: func(ctrl *gomock.Controller) *infra.Request {
				rw := mock_infra.NewMockResponseWriter(ctrl)
				pld := &cert_mgmt.TRC{RawTRC: []byte("test")}
				rw.EXPECT().SendTRCReply(gomock.Any(), pld).Return(nil)
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), rw),
					&cert_mgmt.TRCReq{ISD: 1, Version: scrypto.LatestVer},
					nil, nil, 0,
				)
			},
			Provider: func(ctrl *gomock.Controller) trust.CryptoProvider {
				opts := infra.TRCOpts{
					TrustStoreOpts: infra.TrustStoreOpts{
						LocalOnly: false,
					},
					AllowInactive: true,
				}
				p := mock_v2.NewMockCryptoProvider(ctrl)
				p.EXPECT().GetRawTRC(gomock.Any(), addr.ISD(1), scrypto.LatestVer,
					opts, nil).Return([]byte("test"), nil)
				return p
			},
			ExpectedResult: infra.MetricsResultOk,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			handler := trust.NewTRCReqHandler(
				test.Request(ctrl),
				test.Provider(ctrl),
			)
			result := handler.Handle()
			assert.Equal(t, test.ExpectedResult, result)
		})
	}
}

func TestChainPushHandler(t *testing.T) {
	chain := loadChain(t, ChainDesc{IA: xtest.MustParseIA("1-ff00:0:110"), Version: 1})
	testCases := []*struct {
		Name           string
		Request        func(ctrl *gomock.Controller) *infra.Request
		Inserter       func(ctrl *gomock.Controller) trust.Inserter
		ExpectedResult *infra.HandlerResult
	}{
		{
			Name: "nil request",
			Request: func(_ *gomock.Controller) *infra.Request {
				return nil
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				return mock_v2.NewMockInserter(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		{
			Name: "empty message",
			Request: func(_ *gomock.Controller) *infra.Request {
				return infra.NewRequest(nil, nil, nil, nil, 0)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				return mock_v2.NewMockInserter(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		{
			Name: "bad message type",
			Request: func(_ *gomock.Controller) *infra.Request {
				return infra.NewRequest(nil, &cert_mgmt.TRC{}, nil, nil, 0)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				return mock_v2.NewMockInserter(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		{
			Name: "no response writer",
			Request: func(_ *gomock.Controller) *infra.Request {
				return infra.NewRequest(nil, &cert_mgmt.Chain{}, nil, nil, 0)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				return mock_v2.NewMockInserter(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		{
			Name: "chain cannot be decoded",
			Request: func(ctrl *gomock.Controller) *infra.Request {
				mockRW := mock_infra.NewMockResponseWriter(ctrl)
				mockRW.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), mockRW),
					&cert_mgmt.Chain{
						RawChain: common.RawBytes{1, 2, 3, 4},
					},
					nil,
					nil,
					0,
				)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				return mock_v2.NewMockInserter(ctrl)
			},
			ExpectedResult: infra.MetricsErrInvalid,
		},
		{
			Name: "insert mismatch error",
			Request: func(ctrl *gomock.Controller) *infra.Request {
				mockRW := mock_infra.NewMockResponseWriter(ctrl)
				mockRW.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), mockRW),
					&cert_mgmt.Chain{
						RawChain: chain.Raw,
					},
					nil,
					nil,
					0,
				)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				mockInserter := mock_v2.NewMockInserter(ctrl)
				mockInserter.EXPECT().
					InsertChain(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(trust.ErrContentMismatch)
				return mockInserter
			},
			ExpectedResult: infra.MetricsErrInvalid,
		},
		{
			Name: "insert verification error",
			Request: func(ctrl *gomock.Controller) *infra.Request {
				mockRW := mock_infra.NewMockResponseWriter(ctrl)
				mockRW.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), mockRW),
					&cert_mgmt.Chain{
						RawChain: chain.Raw,
					},
					nil,
					nil,
					0,
				)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				mockInserter := mock_v2.NewMockInserter(ctrl)
				mockInserter.EXPECT().
					InsertChain(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(trust.ErrVerification)
				return mockInserter
			},
			ExpectedResult: infra.MetricsErrInvalid,
		},
		{
			Name: "insert other error",
			Request: func(ctrl *gomock.Controller) *infra.Request {
				mockRW := mock_infra.NewMockResponseWriter(ctrl)
				mockRW.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), mockRW),
					&cert_mgmt.Chain{
						RawChain: chain.Raw,
					},
					nil,
					nil,
					0,
				)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				mockInserter := mock_v2.NewMockInserter(ctrl)
				mockInserter.EXPECT().
					InsertChain(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(serrors.New("foo"))
				return mockInserter
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		{
			Name: "insert success",
			Request: func(ctrl *gomock.Controller) *infra.Request {
				mockRW := mock_infra.NewMockResponseWriter(ctrl)
				mockRW.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), mockRW),
					&cert_mgmt.Chain{
						RawChain: chain.Raw,
					},
					nil,
					nil,
					0,
				)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				mockInserter := mock_v2.NewMockInserter(ctrl)
				mockInserter.EXPECT().InsertChain(gomock.Any(), gomock.Any(), gomock.Any())
				return mockInserter
			},
			ExpectedResult: infra.MetricsResultOk,
		},
	}

	for _, test := range testCases {
		tc := test
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			chainPushHandler := trust.NewChainPushHandler(
				tc.Request(ctrl),
				nil,
				tc.Inserter(ctrl),
			)
			result := chainPushHandler.Handle()
			assert.Equal(t, tc.ExpectedResult, result)
		})
	}
}

func TestTRCPushHandler(t *testing.T) {
	trc := loadTRC(t, TRCDesc{ISD: 1, Version: 1})
	testCases := []*struct {
		Name           string
		Request        func(ctrl *gomock.Controller) *infra.Request
		Inserter       func(ctrl *gomock.Controller) trust.Inserter
		ExpectedResult *infra.HandlerResult
	}{
		{
			Name: "nil request",
			Request: func(_ *gomock.Controller) *infra.Request {
				return nil
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				return mock_v2.NewMockInserter(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		{
			Name: "empty message",
			Request: func(_ *gomock.Controller) *infra.Request {
				return infra.NewRequest(nil, nil, nil, nil, 0)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				return mock_v2.NewMockInserter(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		{
			Name: "bad message type",
			Request: func(_ *gomock.Controller) *infra.Request {
				return infra.NewRequest(nil, &cert_mgmt.Chain{}, nil, nil, 0)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				return mock_v2.NewMockInserter(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		{
			Name: "no response writer",
			Request: func(_ *gomock.Controller) *infra.Request {
				return infra.NewRequest(nil, &cert_mgmt.TRC{}, nil, nil, 0)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				return mock_v2.NewMockInserter(ctrl)
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		{
			Name: "TRC cannot be decoded",
			Request: func(ctrl *gomock.Controller) *infra.Request {
				mockRW := mock_infra.NewMockResponseWriter(ctrl)
				mockRW.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), mockRW),
					&cert_mgmt.TRC{
						RawTRC: common.RawBytes{1, 2, 3, 4},
					},
					nil,
					nil,
					0,
				)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				return mock_v2.NewMockInserter(ctrl)
			},
			ExpectedResult: infra.MetricsErrInvalid,
		},
		{
			Name: "insert mismatch error",
			Request: func(ctrl *gomock.Controller) *infra.Request {
				mockRW := mock_infra.NewMockResponseWriter(ctrl)
				mockRW.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), mockRW),
					&cert_mgmt.TRC{
						RawTRC: trc.Raw,
					},
					nil,
					nil,
					0,
				)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				mockInserter := mock_v2.NewMockInserter(ctrl)
				mockInserter.EXPECT().
					InsertTRC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(trust.ErrContentMismatch)
				return mockInserter
			},
			ExpectedResult: infra.MetricsErrInvalid,
		},
		{
			Name: "insert verification error",
			Request: func(ctrl *gomock.Controller) *infra.Request {
				mockRW := mock_infra.NewMockResponseWriter(ctrl)
				mockRW.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), mockRW),
					&cert_mgmt.TRC{
						RawTRC: trc.Raw,
					},
					nil,
					nil,
					0,
				)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				mockInserter := mock_v2.NewMockInserter(ctrl)
				mockInserter.EXPECT().
					InsertTRC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(trust.ErrVerification)
				return mockInserter
			},
			ExpectedResult: infra.MetricsErrInvalid,
		},
		{
			Name: "insert other error",
			Request: func(ctrl *gomock.Controller) *infra.Request {
				mockRW := mock_infra.NewMockResponseWriter(ctrl)
				mockRW.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), mockRW),
					&cert_mgmt.TRC{
						RawTRC: trc.Raw,
					},
					nil,
					nil,
					0,
				)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				mockInserter := mock_v2.NewMockInserter(ctrl)
				mockInserter.EXPECT().
					InsertTRC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(serrors.New("foo"))
				return mockInserter
			},
			ExpectedResult: infra.MetricsErrInternal,
		},
		{
			Name: "insert success",
			Request: func(ctrl *gomock.Controller) *infra.Request {
				mockRW := mock_infra.NewMockResponseWriter(ctrl)
				mockRW.EXPECT().SendAckReply(gomock.Any(), gomock.Any())
				return infra.NewRequest(
					infra.NewContextWithResponseWriter(context.Background(), mockRW),
					&cert_mgmt.TRC{
						RawTRC: trc.Raw,
					},
					nil,
					nil,
					0,
				)
			},
			Inserter: func(ctrl *gomock.Controller) trust.Inserter {
				mockInserter := mock_v2.NewMockInserter(ctrl)
				mockInserter.EXPECT().InsertTRC(gomock.Any(), gomock.Any(), gomock.Any())
				return mockInserter
			},
			ExpectedResult: infra.MetricsResultOk,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			trcPushHandler := trust.NewTRCPushHandler(
				tc.Request(ctrl),
				nil,
				tc.Inserter(ctrl),
			)
			result := trcPushHandler.Handle()
			assert.Equal(t, tc.ExpectedResult, result)
		})
	}
}
