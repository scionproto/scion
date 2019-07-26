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
	"github.com/scionproto/scion/go/proto"
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
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1},
			},
			Expect: func(api *mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr {
				req := &path_mgmt.SegReq{RawSrcIA: non_core_111.IAInt(), RawDstIA: isd1.IAInt()}
				reply := &path_mgmt.SegReply{
					Req: req,
					Recs: &path_mgmt.SegRecs{
						Recs: []*seg.Meta{{Type: proto.PathSegType_up, Segment: tg.seg120_111}},
					},
				}
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req), gomock.Any(), gomock.Any()).
					Return(reply, nil)
				return []segfetcher.ReplyOrErr{{Reply: reply}}
			},
		},
		"Down only": {
			Req: segfetcher.RequestSet{
				Down: segfetcher.Request{Src: isd1, Dst: non_core_111},
			},
			Expect: func(api *mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr {
				req := &path_mgmt.SegReq{RawSrcIA: isd1.IAInt(), RawDstIA: non_core_111.IAInt()}
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
				return []segfetcher.ReplyOrErr{{Reply: reply}}
			},
		},
		"Cores only": {
			Req: segfetcher.RequestSet{
				Cores: segfetcher.Requests{
					{Src: core_210, Dst: core_110},
					{Src: core_210, Dst: core_120},
					{Src: core_210, Dst: core_130},
				},
			},
			Expect: func(api *mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr {
				req1 := &path_mgmt.SegReq{RawSrcIA: core_210.IAInt(), RawDstIA: core_110.IAInt()}
				testErr := errors.New("test error.")
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req1), gomock.Any(), gomock.Any()).
					Return(nil, testErr)
				req2 := &path_mgmt.SegReq{RawSrcIA: core_210.IAInt(), RawDstIA: core_120.IAInt()}
				reply2 := &path_mgmt.SegReply{
					Req: req2,
					Recs: &path_mgmt.SegRecs{
						Recs: []*seg.Meta{{Type: proto.PathSegType_core, Segment: tg.seg210_120}},
					},
				}
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req2), gomock.Any(), gomock.Any()).
					Return(reply2, nil)
				req3 := &path_mgmt.SegReq{RawSrcIA: core_210.IAInt(), RawDstIA: core_130.IAInt()}
				reply3 := &path_mgmt.SegReply{
					Req: req2,
					Recs: &path_mgmt.SegRecs{
						Recs: []*seg.Meta{{Type: proto.PathSegType_core, Segment: tg.seg210_130}},
					},
				}
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req3), gomock.Any(), gomock.Any()).
					Return(reply3, nil)
				return []segfetcher.ReplyOrErr{{Err: testErr}, {Reply: reply2}, {Reply: reply3}}
			},
		},
		"Up cores": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: segfetcher.Requests{{Src: isd1, Dst: core_210}},
			},
			Expect: func(api *mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr {
				req := &path_mgmt.SegReq{RawSrcIA: non_core_111.IAInt(), RawDstIA: isd1.IAInt()}
				reply := &path_mgmt.SegReply{
					Req: req,
					Recs: &path_mgmt.SegRecs{
						Recs: []*seg.Meta{{Type: proto.PathSegType_up, Segment: tg.seg120_111}},
					},
				}
				api.EXPECT().GetSegs(gomock.Any(), gomock.Eq(req), gomock.Any(), gomock.Any()).
					Return(reply, nil)
				return []segfetcher.ReplyOrErr{{Reply: reply}}
			},
		},
		"Cores down": {
			Req: segfetcher.RequestSet{
				Cores: segfetcher.Requests{{Src: core_210, Dst: isd1}},
				Down:  segfetcher.Request{Src: isd1, Dst: non_core_111},
			},
			Expect: func(api *mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr {
				req := &path_mgmt.SegReq{RawSrcIA: isd1.IAInt(), RawDstIA: non_core_111.IAInt()}
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
				return []segfetcher.ReplyOrErr{{Reply: reply}}
			},
		},
		"Up cores down": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: segfetcher.Requests{{Src: isd1, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
			Expect: func(api *mock_segfetcher.MockRequestAPI) []segfetcher.ReplyOrErr {
				req1 := &path_mgmt.SegReq{RawSrcIA: non_core_111.IAInt(), RawDstIA: isd1.IAInt()}
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
				req2 := &path_mgmt.SegReq{RawSrcIA: isd2.IAInt(), RawDstIA: non_core_211.IAInt()}
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
				return []segfetcher.ReplyOrErr{{Reply: reply1}, {Reply: reply2}}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			destProvider := mock_segfetcher.NewMockDstProvider(ctrl)
			destProvider.EXPECT().Dst(gomock.Any(), gomock.Any()).AnyTimes()
			api := mock_segfetcher.NewMockRequestAPI(ctrl)
			expectedReplies := test.Expect(api)

			requester := segfetcher.Requester{
				API:         api,
				DstProvider: destProvider,
			}
			var replies []segfetcher.ReplyOrErr
			for r := range requester.Request(ctx, test.Req) {
				replies = append(replies, r)
			}
			assert.ElementsMatch(t, expectedReplies, replies)
		})
	}
}
