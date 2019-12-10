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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/mock_v2"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
)

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

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
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
