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

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher/mock_segfetcher"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
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

	req_111_1   = segfetcher.Request{Src: non_core_111, Dst: isd1}
	req_1_111   = segfetcher.Request{Src: isd1, Dst: non_core_111}
	req_1_2     = segfetcher.Request{Src: isd1, Dst: isd2}
	req_1_210   = segfetcher.Request{Src: isd1, Dst: core_210}
	req_2_211   = segfetcher.Request{Src: isd2, Dst: non_core_211}
	req_210_1   = segfetcher.Request{Src: core_210, Dst: isd1}
	req_210_110 = segfetcher.Request{Src: core_210, Dst: core_110}
	req_210_120 = segfetcher.Request{Src: core_210, Dst: core_120}
	req_210_130 = segfetcher.Request{Src: core_210, Dst: core_130}
)

func TestRequester(t *testing.T) {
	rootCtrl := gomock.NewController(t)
	defer rootCtrl.Finish()
	tg := newTestGraph(rootCtrl)

	tests := map[string]struct {
		Req    segfetcher.RequestSet
		Expect func(*mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr
	}{
		"Empty req": {
			Req: segfetcher.RequestSet{},
			Expect: func(api *mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr {
				return nil
			},
		},
		"Up only": {
			Req: segfetcher.RequestSet{
				Up: req_111_1,
			},
			Expect: func(api *mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr {
				req := req_111_1.ToSegReq()
				reply := &path_mgmt.SegReply{
					Req: req,
					Recs: &path_mgmt.SegRecs{
						Recs: []*seg.Meta{{Type: proto.PathSegType_up, Segment: tg.seg120_111}},
					},
				}
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req), gomock.Any(), gomock.Any()).
					Return(reply, nil)
				return []segfetcher.ReplyOrErr{
					{Req: segfetcher.Request{Src: non_core_111, Dst: isd1}, Reply: reply},
				}
			},
		},
		"Down only": {
			Req: segfetcher.RequestSet{
				Down: req_1_111,
			},
			Expect: func(api *mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr {
				req := req_1_111.ToSegReq()
				reply := &path_mgmt.SegReply{
					Req: req,
					Recs: &path_mgmt.SegRecs{
						Recs: []*seg.Meta{
							{Type: proto.PathSegType_down, Segment: tg.seg120_111},
							{Type: proto.PathSegType_down, Segment: tg.seg130_111},
						},
					},
				}
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req), gomock.Any(), gomock.Any()).
					Return(reply, nil)
				return []segfetcher.ReplyOrErr{{Req: req_1_111, Reply: reply}}
			},
		},
		"Cores only": {
			Req: segfetcher.RequestSet{
				Cores: segfetcher.Requests{req_210_110, req_210_120, req_210_130},
			},
			Expect: func(api *mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr {
				req1 := req_210_110.ToSegReq()
				testErr := errors.New("test error.")
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req1), gomock.Any(), gomock.Any()).
					Return(nil, testErr)
				req2 := req_210_120.ToSegReq()
				reply2 := &path_mgmt.SegReply{
					Req: req2,
					Recs: &path_mgmt.SegRecs{
						Recs: []*seg.Meta{{Type: proto.PathSegType_core, Segment: tg.seg210_120}},
					},
				}
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req2), gomock.Any(), gomock.Any()).
					Return(reply2, nil)
				req3 := req_210_130.ToSegReq()
				reply3 := &path_mgmt.SegReply{
					Req: req2,
					Recs: &path_mgmt.SegRecs{
						Recs: []*seg.Meta{{Type: proto.PathSegType_core, Segment: tg.seg210_130}},
					},
				}
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req3), gomock.Any(), gomock.Any()).
					Return(reply3, nil)
				return []segfetcher.ReplyOrErr{
					{Req: req_210_110, Err: testErr},
					{Req: req_210_120, Reply: reply2},
					{Req: req_210_130, Reply: reply3},
				}
			},
		},
		"Up cores": {
			Req: segfetcher.RequestSet{
				Up:    req_111_1,
				Cores: segfetcher.Requests{req_1_210},
			},
			Expect: func(api *mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr {
				req := req_111_1.ToSegReq()
				reply := &path_mgmt.SegReply{
					Req: req,
					Recs: &path_mgmt.SegRecs{
						Recs: []*seg.Meta{{Type: proto.PathSegType_up, Segment: tg.seg120_111}},
					},
				}
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req), gomock.Any(), gomock.Any()).
					Return(reply, nil)
				return []segfetcher.ReplyOrErr{{Req: req_111_1, Reply: reply}}
			},
		},
		"Cores down": {
			Req: segfetcher.RequestSet{
				Cores: segfetcher.Requests{req_210_1},
				Down:  req_1_111,
			},
			Expect: func(api *mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr {
				req := req_1_111.ToSegReq()
				reply := &path_mgmt.SegReply{
					Req: req,
					Recs: &path_mgmt.SegRecs{
						Recs: []*seg.Meta{
							{Type: proto.PathSegType_down, Segment: tg.seg120_111},
							{Type: proto.PathSegType_down, Segment: tg.seg130_111},
						},
					},
				}
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req), gomock.Any(), gomock.Any()).
					Return(reply, nil)
				return []segfetcher.ReplyOrErr{{Req: req_1_111, Reply: reply}}
			},
		},
		"Up cores down": {
			Req: segfetcher.RequestSet{
				Up:    req_111_1,
				Cores: segfetcher.Requests{req_1_2},
				Down:  req_2_211,
			},
			Expect: func(api *mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr {
				req1 := req_111_1.ToSegReq()
				reply1 := &path_mgmt.SegReply{
					Req: req1,
					Recs: &path_mgmt.SegRecs{
						Recs: []*seg.Meta{
							{Type: proto.PathSegType_up, Segment: tg.seg120_111},
							{Type: proto.PathSegType_up, Segment: tg.seg130_111},
						},
					},
				}
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req1), gomock.Any(), gomock.Any()).
					Return(reply1, nil)
				req2 := req_2_211.ToSegReq()
				reply2 := &path_mgmt.SegReply{
					Req: req2,
					Recs: &path_mgmt.SegRecs{
						Recs: []*seg.Meta{
							{Type: proto.PathSegType_down, Segment: tg.seg210_211},
						},
					},
				}
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req2), gomock.Any(), gomock.Any()).
					Return(reply2, nil)
				return []segfetcher.ReplyOrErr{
					{Req: req_111_1, Reply: reply1},
					{Req: req_2_211, Reply: reply2},
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			dstProvider := mock_segfetcher.NewMockDstProvider(ctrl)
			dstProvider.EXPECT().Dst(gomock.Any(), gomock.Any()).AnyTimes()
			api := mock_segfetcher.NewMockRequestAPI(ctrl)
			expectedReplies := test.Expect(api)

			requester := segfetcher.DefaultRequester{
				API:         api,
				DstProvider: dstProvider,
			}
			var replies []segfetcher.ReplyOrErr
			for r := range requester.Request(ctx, test.Req) {
				replies = append(replies, r)
			}
			assert.ElementsMatch(t, expectedReplies, replies)
		})
	}
}
