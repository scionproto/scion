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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

type testGraph struct {
	g *graph.Graph

	seg110_120 *seg.PathSegment
	seg110_130 *seg.PathSegment
	seg130_111 *seg.PathSegment
	seg120_111 *seg.PathSegment

	seg210_120 *seg.PathSegment
	seg210_130 *seg.PathSegment
	seg210_211 *seg.PathSegment
}

func newTestGraph(ctrl *gomock.Controller) *testGraph {
	g := graph.NewDefaultGraph(ctrl)

	return &testGraph{
		g:          g,
		seg110_120: g.Beacon([]common.IFIDType{graph.If_110_X_120_A}),
		seg110_130: g.Beacon([]common.IFIDType{graph.If_110_X_130_A}),
		seg120_111: g.Beacon([]common.IFIDType{graph.If_120_X_111_B}),
		seg130_111: g.Beacon([]common.IFIDType{graph.If_130_B_111_A}),

		seg210_120: g.Beacon([]common.IFIDType{graph.If_210_X_110_X, graph.If_110_X_120_A}),
		seg210_130: g.Beacon([]common.IFIDType{graph.If_210_X_110_X, graph.If_110_X_130_A}),
		seg210_211: g.Beacon([]common.IFIDType{graph.If_210_X_211_A}),
	}
}

type resolverTest struct {
	Req              segfetcher.RequestSet
	InitCache        func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB
	ExpectedSegments segfetcher.Segments
	ExpectedReqSet   segfetcher.RequestSet
}

func (rt resolverTest) run(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := rt.InitCache(ctrl)
	resolver := segfetcher.NewResolver(db)
	segs, remainingReqs, err := resolver.Resolve(context.Background(), rt.Req)
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
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				// no cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd1))
				return db
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1},
			},
		},
		"Up wildcard (cached)": {
			Req: segfetcher.RequestSet{
				Up: segfetcher.Request{Src: non_core_111, Dst: isd1},
			},
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd1)).Return(&futureT, nil)
				db.EXPECT().Get(gomock.Any(), gomock.Eq(&query.Params{
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
				return db
			},
			ExpectedSegments: segfetcher.Segments{
				Up: seg.Segments{tg.seg120_111, tg.seg130_111},
			},
		},
		"Up Core": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: core_110}},
			},
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				// no cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd1))
				return db
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: core_110}},
			},
		},
		"Up(cached) Core": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: core_110}},
			},
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd1)).Return(&futureT, nil)
				db.EXPECT().Get(gomock.Any(), gomock.Eq(&query.Params{
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
				// no cached core segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_110))
				return db
			},
			ExpectedSegments: segfetcher.Segments{Up: seg.Segments{tg.seg120_111, tg.seg130_111}},
			ExpectedReqSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{
					{Src: core_120, Dst: core_110},
					{Src: core_130, Dst: core_110},
				},
			},
		},
		"Up(cached) Core(cached)": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: core_110}},
			},
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd1)).Return(&futureT, nil)
				db.EXPECT().Get(gomock.Any(), gomock.Eq(&query.Params{
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
				// cached core segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_110)).Return(&futureT, nil)
				db.EXPECT().Get(gomock.Any(), gomock.Eq(&query.Params{
					StartsAt: []addr.IA{core_110}, EndsAt: []addr.IA{core_120, core_130},
				})).Return(resultsFromSegs(tg.seg110_120, tg.seg110_130), nil)
				return db
			},
			ExpectedSegments: segfetcher.Segments{
				Up:   seg.Segments{tg.seg120_111, tg.seg130_111},
				Core: seg.Segments{tg.seg110_120, tg.seg110_130},
			},
		},
		"Up Core Down": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				// no cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd1))
				return db
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
		},
		"Up(cached) Core Down": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_111, Dst: isd1},
				Cores: []segfetcher.Request{{Src: isd1, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd1)).Return(&futureT, nil)
				db.EXPECT().Get(gomock.Any(), gomock.Eq(&query.Params{
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_211))
				return db
			},
			ExpectedSegments: segfetcher.Segments{
				Up: seg.Segments{tg.seg120_111, tg.seg130_111},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: isd1, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
		},
		"Up(cached) Core Down(cached)": {
			Req: segfetcher.RequestSet{
				Up:    segfetcher.Request{Src: non_core_211, Dst: isd2},
				Cores: []segfetcher.Request{{Src: isd2, Dst: isd1}},
				Down:  segfetcher.Request{Src: isd1, Dst: non_core_111},
			},
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd2)).Return(&futureT, nil)
				db.EXPECT().Get(gomock.Any(), gomock.Eq(&query.Params{
					StartsAt: []addr.IA{isd2}, EndsAt: []addr.IA{non_core_211},
				})).Return(resultsFromSegs(tg.seg210_211), nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111)).
					Return(&futureT, nil)
				db.EXPECT().Get(gomock.Any(), gomock.Eq(&query.Params{
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_120))
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_130))
				return db
			},
			ExpectedSegments: segfetcher.Segments{
				Up:   seg.Segments{tg.seg210_211},
				Down: seg.Segments{tg.seg120_111, tg.seg130_111},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{
					{Src: core_210, Dst: core_120},
					{Src: core_210, Dst: core_130},
				},
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
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_110))
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_120))
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_130)).Return(&futureT, nil)
				db.EXPECT().Get(gomock.Any(), gomock.Eq(&query.Params{
					StartsAt: []addr.IA{core_130}, EndsAt: []addr.IA{core_210},
				})).Return(resultsFromSegs(tg.seg210_130), nil)
				return db
			},
			ExpectedSegments: segfetcher.Segments{
				Core: seg.Segments{tg.seg210_130},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{
					{Src: core_210, Dst: core_110},
					{Src: core_210, Dst: core_120},
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
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_110)).Return(&futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_120)).Return(&futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_130)).Return(&futureT, nil)
				db.EXPECT().Get(gomock.Any(), gomock.Eq(&query.Params{
					StartsAt: []addr.IA{core_110, core_120, core_130}, EndsAt: []addr.IA{core_210},
				})).Return(resultsFromSegs(tg.seg210_130), nil)
				return db
			},
			ExpectedSegments: segfetcher.Segments{
				Core: seg.Segments{tg.seg210_130},
			},
		},
		"Core Down": {
			Req: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_110, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_211))
				return db
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_110, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
		},
		"Core Down(cached)": {
			Req: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_110, Dst: isd2}},
				Down:  segfetcher.Request{Src: isd2, Dst: non_core_211},
			},
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_211)).
					Return(&futureT, nil)
				db.EXPECT().Get(gomock.Any(), gomock.Eq(&query.Params{
					StartsAt: []addr.IA{isd2}, EndsAt: []addr.IA{non_core_211},
				})).Return(resultsFromSegs(tg.seg210_211), nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_210))
				return db
			},
			ExpectedSegments: segfetcher.Segments{
				Down: seg.Segments{tg.seg210_211},
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_110, Dst: core_210}},
			},
		},
		"Core(cached) Down(cached)": {
			Req: segfetcher.RequestSet{
				Cores: []segfetcher.Request{{Src: core_210, Dst: isd1}},
				Down:  segfetcher.Request{Src: isd1, Dst: non_core_111},
			},
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111)).
					Return(&futureT, nil)
				db.EXPECT().Get(gomock.Any(), gomock.Eq(&query.Params{
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111, tg.seg130_111), nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_120)).Return(&futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_130)).Return(&futureT, nil)
				db.EXPECT().Get(gomock.Any(), gomock.Eq(&query.Params{
					StartsAt: []addr.IA{core_120, core_130}, EndsAt: []addr.IA{core_210},
				})).Return(resultsFromSegs(tg.seg210_120, tg.seg210_130), nil)
				return db
			},
			ExpectedSegments: segfetcher.Segments{
				Down: seg.Segments{tg.seg120_111, tg.seg130_111},
				Core: seg.Segments{tg.seg210_120, tg.seg210_130},
			},
		},
		"Down": {
			Req: segfetcher.RequestSet{
				Down: segfetcher.Request{Src: core_120, Dst: non_core_111},
			},
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				// no cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111))
				return db
			},
			ExpectedReqSet: segfetcher.RequestSet{
				Down: segfetcher.Request{Src: core_120, Dst: non_core_111},
			},
		},
		"Down(cached)": {
			Req: segfetcher.RequestSet{
				Down: segfetcher.Request{Src: core_120, Dst: non_core_111},
			},
			InitCache: func(ctrl *gomock.Controller) *mock_pathdb.MockPathDB {
				db := mock_pathdb.NewMockPathDB(ctrl)
				// no cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111)).
					Return(&futureT, nil)
				db.EXPECT().Get(gomock.Any(), gomock.Eq(&query.Params{
					StartsAt: []addr.IA{core_120}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111), nil)
				return db
			},
			ExpectedSegments: segfetcher.Segments{
				Down: seg.Segments{tg.seg120_111},
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
