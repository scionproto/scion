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
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/revcache/mock_revcache"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/lib/xtest/matchers"
	"github.com/scionproto/scion/go/proto"
)

type testGraph struct {
	g *graph.Graph

	seg110_120 *seg.PathSegment
	seg110_130 *seg.PathSegment
	seg130_111 *seg.PathSegment
	seg120_111 *seg.PathSegment

	seg210_120   *seg.PathSegment
	seg210_130   *seg.PathSegment
	seg210_130_2 *seg.PathSegment
	seg210_211   *seg.PathSegment
	seg210_212   *seg.PathSegment
}

func newTestGraph(ctrl *gomock.Controller) *testGraph {
	g := graph.NewDefaultGraph(ctrl)

	return &testGraph{
		g:          g,
		seg110_120: g.Beacon([]common.IFIDType{graph.If_110_X_120_A}, false),
		seg110_130: g.Beacon([]common.IFIDType{graph.If_110_X_130_A}, false),
		seg120_111: g.Beacon([]common.IFIDType{graph.If_120_X_111_B}, false),
		seg130_111: g.Beacon([]common.IFIDType{graph.If_130_B_111_A}, false),

		seg210_120: g.Beacon([]common.IFIDType{graph.If_210_X_110_X, graph.If_110_X_120_A}, false),
		seg210_130: g.Beacon([]common.IFIDType{graph.If_210_X_110_X, graph.If_110_X_130_A}, false),
		seg210_130_2: g.Beacon([]common.IFIDType{graph.If_210_X_220_X,
			graph.If_220_X_120_B, graph.If_120_A_130_B}, false),
		seg210_211: g.Beacon([]common.IFIDType{graph.If_210_X_211_A}, false),
		seg210_212: g.Beacon([]common.IFIDType{graph.If_210_X_211_A, graph.If_211_A_212_X}, false),
	}
}

type resolverTest struct {
	Req              segfetcher.RequestSet
	Segs             segfetcher.Segments
	ExpectCalls      func(db *mock_pathdb.MockPathDB)
	ExpectRevcache   func(t *testing.T, revCache *mock_revcache.MockRevCache)
	ExpectedSegments segfetcher.Segments
	ExpectedReqSet   segfetcher.RequestSet
}

func (rt resolverTest) run(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mock_pathdb.NewMockPathDB(ctrl)
	rt.ExpectCalls(db)
	revCache := mock_revcache.NewMockRevCache(ctrl)
	if rt.ExpectRevcache != nil {
		rt.ExpectRevcache(t, revCache)
	} else {
		revCache.EXPECT().Get(gomock.Any(), gomock.Any()).AnyTimes()
	}
	resolver := segfetcher.NewResolver(db, revCache, neverLocal{})
	segs, remainingReqs, err := resolver.Resolve(context.Background(), rt.Segs, rt.Req)
	assert.Equal(t, rt.ExpectedSegments, segs)
	assert.Equal(t, rt.ExpectedReqSet, remainingReqs)
	assert.NoError(t, err)
}

func TestResolver(t *testing.T) {
	rootCtrl := gomock.NewController(t)
	defer rootCtrl.Finish()
	tg := newTestGraph(rootCtrl)
	futureT := time.Now().Add(2 * time.Minute)

	tests := map[string]resolverTest{
		"Up wildcard": {
			Req: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// no cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any())
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Fetch},
			},
		},
		"Up wildcard (cached)": {
			Req: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
			},
			ExpectedSegments: segfetcher.Segments{
				Up: seg.Segments{tg.seg120_111, tg.seg130_111},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Loaded},
			},
		},
		"Up wildcard (fetched)": {
			Req: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Fetched},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
			},
			ExpectedSegments: segfetcher.Segments{
				Up: seg.Segments{tg.seg120_111, tg.seg130_111},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Loaded},
			},
		},
		"Up Core": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: core_110}},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// no cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any())
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Fetch},
				Cores: []segfetcher.Request{
					{Src: isd1, Dst: core_110, State: segfetcher.Unresolved},
				},
			},
		},
		"Up(cached) Core": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: core_110}},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
				// no cached core segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_120),
					gomock.Eq(core_110), gomock.Any())
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_130),
					gomock.Eq(core_110), gomock.Any())
			},
			ExpectedSegments: segfetcher.Segments{Up: seg.Segments{tg.seg120_111, tg.seg130_111}},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Loaded},
				Cores: []segfetcher.Request{
					{Src: core_120, Dst: core_110, State: segfetcher.Fetch},
					{Src: core_130, Dst: core_110, State: segfetcher.Fetch},
				},
			},
		},
		"Up(cached) Core(cached)": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: core_110}},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
				// cached core segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_120),
					gomock.Eq(core_110), gomock.Any()).Return(futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_130),
					gomock.Eq(core_110), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_core},
					StartsAt: []addr.IA{core_110}, EndsAt: []addr.IA{core_120},
				})).Return(resultsFromSegs(tg.seg110_120), nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_core},
					StartsAt: []addr.IA{core_110}, EndsAt: []addr.IA{core_130},
				})).Return(resultsFromSegs(tg.seg110_130), nil)
			},
			ExpectedSegments: segfetcher.Segments{
				Up:   seg.Segments{tg.seg120_111, tg.seg130_111},
				Core: seg.Segments{tg.seg110_120, tg.seg110_130},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Loaded},
				Cores: []segfetcher.Request{
					{Src: core_120, Dst: core_110, State: segfetcher.Loaded},
					{Src: core_130, Dst: core_110, State: segfetcher.Loaded},
				},
			},
		},
		"Up(fetched) Core(fetched)": {
			Req: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Fetched},
				Cores: []segfetcher.Request{
					{Src: core_120, Dst: core_110, State: segfetcher.Fetched},
					{Src: core_130, Dst: core_110, State: segfetcher.Fetched},
				},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_core},
					StartsAt: []addr.IA{core_110}, EndsAt: []addr.IA{core_120},
				})).Return(resultsFromSegs(tg.seg110_120), nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_core},
					StartsAt: []addr.IA{core_110}, EndsAt: []addr.IA{core_130},
				})).Return(resultsFromSegs(tg.seg110_130), nil)
			},
			ExpectedSegments: segfetcher.Segments{
				Up:   seg.Segments{tg.seg120_111, tg.seg130_111},
				Core: seg.Segments{tg.seg110_120, tg.seg110_130},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Loaded},
				Cores: []segfetcher.Request{
					{Src: core_120, Dst: core_110, State: segfetcher.Loaded},
					{Src: core_130, Dst: core_110, State: segfetcher.Loaded},
				},
			},
		},
		"Up(passed) Core": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Loaded},
				Cores: []segfetcher.Request{{Src: core_120, Dst: core_110}},
			},
			Segs: segfetcher.Segments{
				Up: seg.Segments{tg.seg120_111},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_120),
					gomock.Eq(core_110), gomock.Any())
			},
			ExpectedSegments: segfetcher.Segments{
				Up: seg.Segments{tg.seg120_111},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Loaded},
				Cores: []segfetcher.Request{
					{Src: core_120, Dst: core_110, State: segfetcher.Fetch},
				},
			},
		},
		"Up down": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_211, Dst: isd2},
				Cores: []segfetcher.Request{{Src: isd2, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_212},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), non_core_211, isd2, gomock.Any())
				db.EXPECT().GetNextQuery(gomock.Any(), isd2, non_core_212, gomock.Any())
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_211, Dst: isd2, State: segfetcher.Fetch},
				Cores: []segfetcher.Request{{Src: isd2, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_212, State: segfetcher.Fetch},
			},
		},
		"Up(cached) down(cached)": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_211, Dst: isd2},
				Cores: []segfetcher.Request{{Src: isd2, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_212},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), non_core_211, isd2, gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), isd2, non_core_212, gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd2}, EndsAt: []addr.IA{non_core_211},
				})).Return(resultsFromSegs(tg.seg210_211), nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_down},
					StartsAt: []addr.IA{isd2}, EndsAt: []addr.IA{non_core_212},
				})).Return(resultsFromSegs(tg.seg210_212), nil)
			},
			ExpectedSegments: segfetcher.Segments{
				Up:   seg.Segments{tg.seg210_211},
				Down: seg.Segments{tg.seg210_212},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up:   segfetcher.Request{Src: non_core_211, Dst: isd2, State: segfetcher.Loaded},
				Down: segfetcher.Request{Src: isd2, Dst: non_core_212, State: segfetcher.Loaded},
			},
		},
		"Up Core Down": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// no cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any())
				// no cached down segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd2),
					gomock.Eq(non_core_211), gomock.Any())
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Fetch},
				Cores: []segfetcher.Request{{Src: isd1, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211, State: segfetcher.Fetch},
			},
		},
		"Up(cached) Core Down": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd2),
					gomock.Eq(non_core_211), gomock.Any())
			},
			ExpectedSegments: segfetcher.Segments{
				Up: seg.Segments{tg.seg120_111, tg.seg130_111},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Loaded},
				Cores: []segfetcher.Request{{Src: isd1, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211, State: segfetcher.Fetch},
			},
		},
		"Up(cached) Core Down(cached)": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_211, Dst: isd2},
				Cores: []segfetcher.Request{{Src: isd2, Dst: isd1}},
				Down:  segfetcher.Request{Src: isd1, Dst: non_core_111},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_211),
					gomock.Eq(isd2), gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd2}, EndsAt: []addr.IA{non_core_211},
				})).Return(resultsFromSegs(tg.seg210_211), nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd1),
					gomock.Eq(non_core_111), gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_down},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_120), gomock.Any())
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_130), gomock.Any())
			},
			ExpectedSegments: segfetcher.Segments{
				Up:   seg.Segments{tg.seg210_211},
				Down: seg.Segments{tg.seg120_111, tg.seg130_111},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_211, Dst: isd2, State: segfetcher.Loaded},
				Cores: []segfetcher.Request{
					{Src: core_210, Dst: core_120, State: segfetcher.Fetch},
					{Src: core_210, Dst: core_130, State: segfetcher.Fetch},
				},
				Down: segfetcher.Request{Src: isd1, Dst: non_core_111, State: segfetcher.Loaded},
			},
		},
		"Up (0 cached) Core Down(cached)": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_211, Dst: isd2},
				Cores: []segfetcher.Request{{Src: isd2, Dst: isd1}},
				Down:  segfetcher.Request{Src: isd1, Dst: non_core_111},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_211),
					gomock.Eq(isd2), gomock.Any()).
					Return(futureT, nil)
				// return no up segments
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd2}, EndsAt: []addr.IA{non_core_211},
				}))
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd1),
					gomock.Eq(non_core_111), gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_down},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
			},
			ExpectedSegments: segfetcher.Segments{
				Up:   seg.Segments{},
				Down: seg.Segments{tg.seg120_111, tg.seg130_111},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_211, Dst: isd2, State: segfetcher.Loaded},
				Cores: []segfetcher.Request{
					{Src: isd2, Dst: isd1, State: segfetcher.Loaded},
				},
				Down: segfetcher.Request{Src: isd1, Dst: non_core_111, State: segfetcher.Loaded},
			},
		},
		"Up(passed) Core Down(passed)": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_211, Dst: isd2, State: segfetcher.Loaded},
				Cores: []segfetcher.Request{{Src: isd2, Dst: isd1}},
				Down:  segfetcher.Request{Src: isd1, Dst: non_core_111, State: segfetcher.Loaded},
			},
			Segs: segfetcher.Segments{
				Up:   seg.Segments{tg.seg210_211},
				Down: seg.Segments{tg.seg120_111},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_120), gomock.Any())
			},
			ExpectedSegments: segfetcher.Segments{
				Up:   seg.Segments{tg.seg210_211},
				Down: seg.Segments{tg.seg120_111},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_211, Dst: isd2, State: segfetcher.Loaded},
				Cores: []segfetcher.Request{
					{Src: core_210, Dst: core_120, State: segfetcher.Fetch},
				},
				Down: segfetcher.Request{Src: isd1, Dst: non_core_111, State: segfetcher.Loaded},
			},
		},
		"Core(partial cached)": {
			Req: segfetcher.RequestSet{
				Cores: []segfetcher.Request{
					{Src: core_210, Dst: core_110},
					{Src: core_210, Dst: core_120},
					{Src: core_210, Dst: core_130},
				},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_110), gomock.Any())
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_120), gomock.Any())
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_130), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_core},
					StartsAt: []addr.IA{core_130}, EndsAt: []addr.IA{core_210},
				})).Return(resultsFromSegs(tg.seg210_130), nil)
			},
			ExpectedSegments: segfetcher.Segments{
				Core: seg.Segments{tg.seg210_130},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{
					{Src: core_210, Dst: core_110, State: segfetcher.Fetch},
					{Src: core_210, Dst: core_120, State: segfetcher.Fetch},
					{Src: core_210, Dst: core_130, State: segfetcher.Loaded},
				},
			},
		},
		"Core(cached)": {
			Req: segfetcher.RequestSet{
				Cores: []segfetcher.Request{
					{Src: core_210, Dst: core_110},
					{Src: core_210, Dst: core_120},
					{Src: core_210, Dst: core_130},
				},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_110), gomock.Any()).Return(futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_120), gomock.Any()).Return(futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_130), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_core},
					StartsAt: []addr.IA{core_130}, EndsAt: []addr.IA{core_210},
				})).Return(resultsFromSegs(tg.seg210_130), nil)
				// no result cached for the others
				db.EXPECT().Get(gomock.Any(), gomock.Any()).Times(2)
			},
			ExpectedSegments: segfetcher.Segments{
				Core: seg.Segments{tg.seg210_130},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{
					{Src: core_210, Dst: core_110, State: segfetcher.Loaded},
					{Src: core_210, Dst: core_120, State: segfetcher.Loaded},
					{Src: core_210, Dst: core_130, State: segfetcher.Loaded},
				},
			},
		},
		"Core Down": {
			Req: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_110, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd2),
					gomock.Eq(non_core_211), gomock.Any())
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_110, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211, State: segfetcher.Fetch},
			},
		},
		"Core Down(cached)": {
			Req: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_110, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd2),
					gomock.Eq(non_core_211), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_down},
					StartsAt: []addr.IA{isd2}, EndsAt: []addr.IA{non_core_211},
				})).Return(resultsFromSegs(tg.seg210_211), nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_110),
					gomock.Eq(core_210), gomock.Any())
			},
			ExpectedSegments: segfetcher.Segments{
				Down: seg.Segments{tg.seg210_211},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{
					{Src: core_110, Dst: core_210, State: segfetcher.Fetch},
				},
				Down: segfetcher.Request{Src: isd2, Dst: non_core_211, State: segfetcher.Loaded},
			},
		},
		"Core Down(passed)": {
			Req: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_110, Dst: core_210}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211, State: segfetcher.Loaded},
			},
			Segs: segfetcher.Segments{
				Down: seg.Segments{tg.seg210_211},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_110),
					gomock.Eq(core_210), gomock.Any())
			},
			ExpectedSegments: segfetcher.Segments{
				Down: seg.Segments{tg.seg210_211},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{
					{Src: core_110, Dst: core_210, State: segfetcher.Fetch},
				},
				Down: segfetcher.Request{Src: isd2, Dst: non_core_211, State: segfetcher.Loaded},
			},
		},
		"Core(cached) Down(cached)": {
			Req: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_210, Dst: isd1}},
				Down:  segfetcher.Request{Src: isd1, Dst: non_core_111},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd1),
					gomock.Eq(non_core_111), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_down},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_120), gomock.Any()).Return(futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_130), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_core},
					StartsAt: []addr.IA{core_120}, EndsAt: []addr.IA{core_210},
				})).Return(resultsFromSegs(tg.seg210_120), nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_core},
					StartsAt: []addr.IA{core_130}, EndsAt: []addr.IA{core_210},
				})).Return(resultsFromSegs(tg.seg210_130), nil)
			},
			ExpectedSegments: segfetcher.Segments{
				Down: seg.Segments{tg.seg120_111, tg.seg130_111},
				Core: seg.Segments{tg.seg210_120, tg.seg210_130},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{
					{Src: core_210, Dst: core_120, State: segfetcher.Loaded},
					{Src: core_210, Dst: core_130, State: segfetcher.Loaded},
				},
				Down: segfetcher.Request{Src: isd1, Dst: non_core_111, State: segfetcher.Loaded},
			},
		},
		"Down": {
			Req: segfetcher.RequestSet{
				Down: segfetcher.Request{Src: core_120, Dst: non_core_111},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// no cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_120),
					gomock.Eq(non_core_111), gomock.Any())

			},
			ExpectedReqSet: segfetcher.RequestSet{
				Down: segfetcher.Request{Src: core_120, Dst: non_core_111, State: segfetcher.Fetch},
			},
		},
		"Down(cached)": {
			Req: segfetcher.RequestSet{
				Down: segfetcher.Request{Src: core_120, Dst: non_core_111},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// no cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_120),
					gomock.Eq(non_core_111), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_down},
					StartsAt: []addr.IA{core_120}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111), nil)
			},
			ExpectedSegments: segfetcher.Segments{
				Down: seg.Segments{tg.seg120_111},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Down: segfetcher.Request{Src: core_120, Dst: non_core_111,
					State: segfetcher.Loaded},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, test.run)
	}
}

func TestResolverCacheBypass(t *testing.T) {
	rootCtrl := gomock.NewController(t)
	defer rootCtrl.Finish()
	tg := newTestGraph(rootCtrl)
	// futureT := time.Now().Add(2 * time.Minute)

	tests := map[string]resolverTest{
		"Up(cache-bypass) Core Down(cache-bypass)": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_211, Dst: isd2},
				Cores: []segfetcher.Request{{Src: isd2, Dst: isd1}},
				Down:  segfetcher.Request{Src: isd1, Dst: non_core_111},
				Fetch: true,
			},
			ExpectCalls:      func(db *mock_pathdb.MockPathDB) {},
			ExpectedSegments: segfetcher.Segments{},
			ExpectedReqSet: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_211, Dst: isd2, State: segfetcher.Fetch},
				Cores: []segfetcher.Request{{Src: isd2, Dst: isd1}},
				Down:  segfetcher.Request{Src: isd1, Dst: non_core_111, State: segfetcher.Fetch},
				Fetch: true,
			},
		},
		"Up(fetched) Core Down(fetched)": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{State: segfetcher.Fetched, Src: non_core_211, Dst: isd2},
				Cores: []segfetcher.Request{{Src: isd2, Dst: isd1}},
				Down:  segfetcher.Request{State: segfetcher.Fetched, Src: isd1, Dst: non_core_111},
				Fetch: true,
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// cached up segments
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd2}, EndsAt: []addr.IA{non_core_211},
				})).Return(resultsFromSegs(tg.seg210_211), nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_down},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
			},
			ExpectedSegments: segfetcher.Segments{
				Up:   seg.Segments{tg.seg210_211},
				Down: seg.Segments{tg.seg120_111, tg.seg130_111},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_211, Dst: isd2, State: segfetcher.Loaded},
				Cores: []segfetcher.Request{
					{Src: core_210, Dst: core_120, State: segfetcher.Fetch},
					{Src: core_210, Dst: core_130, State: segfetcher.Fetch},
				},
				Down:  segfetcher.Request{Src: isd1, Dst: non_core_111, State: segfetcher.Loaded},
				Fetch: true,
			},
		},
	}
	for name, test := range tests {
		t.Run(name, test.run)
	}
}

func TestResolverWithRevocations(t *testing.T) {
	rootCtrl := gomock.NewController(t)
	defer rootCtrl.Finish()
	tg := newTestGraph(rootCtrl)
	futureT := time.Now().Add(2 * time.Minute)

	revoke := func(t *testing.T, revCache *mock_revcache.MockRevCache, key revcache.Key) {
		ksMatcher := keySetContains{keys: []revcache.Key{key}}
		srev, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{}, infra.NullSigner)
		require.NoError(t, err)
		revCache.EXPECT().Get(gomock.Any(), ksMatcher).
			Return(revcache.Revocations{key: srev}, nil)
	}
	tests := map[string]resolverTest{
		"Up wildcard (cached)": {
			Req: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
			},
			ExpectRevcache: func(t *testing.T, revCache *mock_revcache.MockRevCache) {
				key111_120 := revcache.Key{IA: non_core_111, IfId: graph.If_111_B_120_X}
				key111_130 := revcache.Key{IA: non_core_111, IfId: graph.If_111_A_130_B}
				revoke(t, revCache, key111_120)
				revoke(t, revCache, key111_130)
				revCache.EXPECT().Get(gomock.Any(), gomock.Any()).AnyTimes()
			},
			// On the initial fetch, if everything is revoked, just try again
			// and fetch it.
			ExpectedSegments: segfetcher.Segments{},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1, State: segfetcher.Fetch},
			},
		},
		"Core (cached) with revocations returns full result": {
			Req: segfetcher.RequestSet{
				Cores: []segfetcher.Request{
					{Src: core_210, Dst: core_110},
					{Src: core_210, Dst: core_120},
					{Src: core_210, Dst: core_130},
				},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_110), gomock.Any()).Return(futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_120), gomock.Any()).Return(futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210),
					gomock.Eq(core_130), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_core},
					StartsAt: []addr.IA{core_130}, EndsAt: []addr.IA{core_210},
				})).Return(resultsFromSegs(tg.seg210_130, tg.seg210_130_2), nil)
				// Other calls return 0
				db.EXPECT().Get(gomock.Any(), gomock.Any()).Times(2)
			},
			ExpectRevcache: func(t *testing.T, revCache *mock_revcache.MockRevCache) {
				key110 := revcache.Key{IA: core_110, IfId: graph.If_110_X_130_A}
				ksMatcher := keySetContains{keys: []revcache.Key{key110}}
				srev, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{}, infra.NullSigner)
				require.NoError(t, err)
				revCache.EXPECT().Get(gomock.Any(), ksMatcher).Return(revcache.Revocations{
					key110: srev,
				}, nil)
				revCache.EXPECT().Get(gomock.Any(), gomock.Any()).AnyTimes()
			},
			ExpectedSegments: segfetcher.Segments{
				Core: seg.Segments{tg.seg210_130, tg.seg210_130_2},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{
					{Src: core_210, Dst: core_110, State: segfetcher.Loaded},
					{Src: core_210, Dst: core_120, State: segfetcher.Loaded},
					{Src: core_210, Dst: core_130, State: segfetcher.Loaded},
				},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, test.run)
	}
}

func resultsFromSegs(segs ...*seg.PathSegment) query.Results {
	results := make(query.Results, 0, len(segs))
	for _, seg := range segs {
		results = append(results, &query.Result{
			Seg:        seg,
			LastUpdate: time.Now().Add(-2 * time.Minute),
		})
	}
	return results
}

type keySetContains struct {
	keys []revcache.Key
}

func (m keySetContains) Matches(other interface{}) bool {
	ks, ok := other.(revcache.KeySet)
	if !ok {
		return false
	}
	for _, k := range m.keys {
		if _, ok := ks[k]; !ok {
			return false
		}
	}
	return true
}

func (m keySetContains) String() string {
	return fmt.Sprintf("revcache.KeySet containing %v", m.keys)
}

type neverLocal struct{}

func (neverLocal) IsSegLocal(_ context.Context, _, _ addr.IA) (bool, error) { return false, nil }
