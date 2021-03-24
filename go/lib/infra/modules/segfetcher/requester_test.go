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

package segfetcher_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher/mock_segfetcher"
	"github.com/scionproto/scion/go/lib/xtest"
)

const (
	Up   = seg.TypeUp
	Down = seg.TypeDown
	Core = seg.TypeCore
)

var (
	isd1 = xtest.MustParseIA("1-0")
	isd2 = xtest.MustParseIA("2-0")

	core_110 = xtest.MustParseIA("1-ff00:0:110")
	core_120 = xtest.MustParseIA("1-ff00:0:120")
	core_130 = xtest.MustParseIA("1-ff00:0:130")
	core_210 = xtest.MustParseIA("2-ff00:0:210")

	non_core_111 = xtest.MustParseIA("1-ff00:0:111")
	non_core_112 = xtest.MustParseIA("1-ff00:0:112")
	non_core_211 = xtest.MustParseIA("2-ff00:0:211")
	non_core_212 = xtest.MustParseIA("2-ff00:0:212")

	req_111_1   = segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1}
	req_1_111   = segfetcher.Request{SegType: Down, Src: isd1, Dst: non_core_111}
	req_2_211   = segfetcher.Request{SegType: Down, Src: isd2, Dst: non_core_211}
	req_210_110 = segfetcher.Request{SegType: Core, Src: core_210, Dst: core_110}
	req_210_120 = segfetcher.Request{SegType: Core, Src: core_210, Dst: core_120}
	req_210_130 = segfetcher.Request{SegType: Core, Src: core_210, Dst: core_130}
)

func TestRequester(t *testing.T) {
	rootCtrl := gomock.NewController(t)
	defer rootCtrl.Finish()
	tg := newTestGraph(rootCtrl)
	const maxRetries = 13

	tests := map[string]struct {
		Reqs   segfetcher.Requests
		Expect func(*mock_segfetcher.MockRPC) []segfetcher.ReplyOrErr
	}{
		"Empty req": {
			Reqs: segfetcher.Requests{},
			Expect: func(api *mock_segfetcher.MockRPC) []segfetcher.ReplyOrErr {
				return nil
			},
		},
		"Up only": {
			Reqs: segfetcher.Requests{req_111_1},
			Expect: func(api *mock_segfetcher.MockRPC) []segfetcher.ReplyOrErr {
				req := req_111_1
				reply := []*seg.Meta{tg.seg120_111_up}
				api.EXPECT().Segments(gomock.Any(), gomock.Eq(req), gomock.Any()).
					Return(reply, nil)
				return []segfetcher.ReplyOrErr{{Req: req_111_1, Segments: reply}}
			},
		},
		"Down only": {
			Reqs: segfetcher.Requests{req_1_111},
			Expect: func(api *mock_segfetcher.MockRPC) []segfetcher.ReplyOrErr {
				req := req_1_111
				reply := []*seg.Meta{tg.seg120_111_down, tg.seg130_111_down}
				api.EXPECT().Segments(gomock.Any(), gomock.Eq(req), gomock.Any()).
					Return(reply, nil)
				return []segfetcher.ReplyOrErr{{Req: req_1_111, Segments: reply}}
			},
		},
		"Cores only": {
			Reqs: segfetcher.Requests{req_210_110, req_210_120, req_210_130},
			Expect: func(api *mock_segfetcher.MockRPC) []segfetcher.ReplyOrErr {
				// req1 expriences unspecific error, retries until maxTries
				req1 := req_210_110
				expectedErr1 := errors.New("no attempts left")
				api.EXPECT().Segments(gomock.Any(), gomock.Eq(req1), gomock.Any()).
					Times(maxRetries+1).Return(nil, errors.New("some error"))
				// req2 sees ErrNotReachable, aborts immediately after first try
				req2 := req_210_120
				expectedErr2 := segfetcher.ErrNotReachable
				api.EXPECT().Segments(gomock.Any(), gomock.Eq(req2), gomock.Any()).
					Return(nil, segfetcher.ErrNotReachable)
				req3 := req_210_130
				reply3 := []*seg.Meta{tg.seg210_130_core}
				api.EXPECT().Segments(gomock.Any(), gomock.Eq(req3), gomock.Any()).
					Return(reply3, nil)
				return []segfetcher.ReplyOrErr{
					{Req: req_210_110, Err: expectedErr1},
					{Req: req_210_120, Err: expectedErr2},
					{Req: req_210_130, Segments: reply3},
				}
			},
		},
		"Up cores": {
			Reqs: segfetcher.Requests{req_111_1},
			Expect: func(api *mock_segfetcher.MockRPC) []segfetcher.ReplyOrErr {
				req := req_111_1
				reply := []*seg.Meta{tg.seg120_111_up}
				api.EXPECT().Segments(gomock.Any(), gomock.Eq(req), gomock.Any()).
					Return(reply, nil)
				return []segfetcher.ReplyOrErr{{Req: req_111_1, Segments: reply}}
			},
		},
		"Cores down": {
			Reqs: segfetcher.Requests{req_1_111},
			Expect: func(api *mock_segfetcher.MockRPC) []segfetcher.ReplyOrErr {
				req := req_1_111
				reply := []*seg.Meta{tg.seg120_111_down, tg.seg130_111_down}
				api.EXPECT().Segments(gomock.Any(), gomock.Eq(req), gomock.Any()).
					Return(reply, nil)
				return []segfetcher.ReplyOrErr{{Req: req_1_111, Segments: reply}}
			},
		},
		"Up cores down": {
			Reqs: segfetcher.Requests{req_111_1, req_2_211},
			Expect: func(api *mock_segfetcher.MockRPC) []segfetcher.ReplyOrErr {
				req1 := req_111_1
				reply1 := []*seg.Meta{tg.seg120_111_up, tg.seg130_111_up}
				api.EXPECT().Segments(gomock.Any(), gomock.Eq(req1), gomock.Any()).
					Return(reply1, nil)
				req2 := req_2_211
				reply2 := []*seg.Meta{tg.seg210_211_down}
				api.EXPECT().Segments(gomock.Any(), gomock.Eq(req2), gomock.Any()).
					Return(reply2, nil)
				return []segfetcher.ReplyOrErr{
					{Req: req_111_1, Segments: reply1},
					{Req: req_2_211, Segments: reply2},
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancelF()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			dstProvider := mock_segfetcher.NewMockDstProvider(ctrl)
			dstProvider.EXPECT().Dst(gomock.Any(), gomock.Any()).AnyTimes()
			rpc := mock_segfetcher.NewMockRPC(ctrl)
			expectedReplies := test.Expect(rpc)

			requester := segfetcher.DefaultRequester{
				RPC:         rpc,
				DstProvider: dstProvider,
				MaxRetries:  maxRetries,
			}
			var replies []segfetcher.ReplyOrErr
			for r := range requester.Request(ctx, test.Reqs) {
				replies = append(replies, r)
			}
			assert.ElementsMatch(t, expectedReplies, replies)
		})
	}
}
