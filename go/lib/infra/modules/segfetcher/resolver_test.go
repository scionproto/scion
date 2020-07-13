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

	seg110_120_core *seg.Meta
	seg110_130_core *seg.Meta
	seg130_111_up   *seg.Meta
	seg130_111_down *seg.Meta
	seg120_111_up   *seg.Meta
	seg120_111_down *seg.Meta

	seg210_120_core   *seg.Meta
	seg210_130_core   *seg.Meta
	seg210_130_2_core *seg.Meta
	seg210_211_up     *seg.Meta
	seg210_211_down   *seg.Meta
	seg210_212_up     *seg.Meta
	seg210_212_down   *seg.Meta
}

func newTestGraph(ctrl *gomock.Controller) *testGraph {
	g := graph.NewDefaultGraph(ctrl)

	seg110_120 := g.Beacon([]common.IFIDType{graph.If_110_X_120_A})
	seg110_130 := g.Beacon([]common.IFIDType{graph.If_110_X_130_A})
	seg120_111 := g.Beacon([]common.IFIDType{graph.If_120_X_111_B})
	seg130_111 := g.Beacon([]common.IFIDType{graph.If_130_B_111_A})

	seg210_120 := g.Beacon([]common.IFIDType{graph.If_210_X_110_X, graph.If_110_X_120_A})
	seg210_130 := g.Beacon([]common.IFIDType{graph.If_210_X_110_X, graph.If_110_X_130_A})
	seg210_130_2 := g.Beacon([]common.IFIDType{graph.If_210_X_220_X,
		graph.If_220_X_120_B, graph.If_120_A_130_B})
	seg210_211 := g.Beacon([]common.IFIDType{graph.If_210_X_211_A})
	seg210_212 := g.Beacon([]common.IFIDType{graph.If_210_X_211_A, graph.If_211_A_212_X})

	return &testGraph{
		g:               g,
		seg110_120_core: &seg.Meta{Type: Core, Segment: seg110_120},
		seg110_130_core: &seg.Meta{Type: Core, Segment: seg110_130},
		seg130_111_up:   &seg.Meta{Type: Up, Segment: seg130_111},
		seg130_111_down: &seg.Meta{Type: Down, Segment: seg130_111},
		seg120_111_up:   &seg.Meta{Type: Up, Segment: seg120_111},
		seg120_111_down: &seg.Meta{Type: Down, Segment: seg120_111},

		seg210_120_core:   &seg.Meta{Type: Core, Segment: seg210_120},
		seg210_130_core:   &seg.Meta{Type: Core, Segment: seg210_130},
		seg210_130_2_core: &seg.Meta{Type: Core, Segment: seg210_130_2},
		seg210_211_up:     &seg.Meta{Type: Up, Segment: seg210_211},
		seg210_211_down:   &seg.Meta{Type: Down, Segment: seg210_211},
		seg210_212_up:     &seg.Meta{Type: Up, Segment: seg210_212},
		seg210_212_down:   &seg.Meta{Type: Down, Segment: seg210_212},
	}
}

type resolverTest struct {
	Reqs              segfetcher.Requests
	Refresh           bool
	Segs              segfetcher.Segments
	ExpectCalls       func(db *mock_pathdb.MockPathDB)
	ExpectRevcache    func(t *testing.T, revCache *mock_revcache.MockRevCache)
	ExpectedSegments  segfetcher.Segments
	ExpectedFetchReqs segfetcher.Requests
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
	segs, fetchReqs, err := resolver.Resolve(context.Background(), rt.Reqs, rt.Refresh)
	assert.Equal(t, rt.ExpectedSegments, segs)
	assert.Equal(t, rt.ExpectedFetchReqs, fetchReqs)
	assert.NoError(t, err)
}

func TestResolver(t *testing.T) {
	rootCtrl := gomock.NewController(t)
	defer rootCtrl.Finish()
	tg := newTestGraph(rootCtrl)
	futureT := time.Now().Add(2 * time.Minute)

	tests := map[string]resolverTest{
		"Up wildcard": {
			Reqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// no cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any())
			},
			ExpectedFetchReqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
			},
		},
		"Up wildcard (cached)": {
			Reqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111_up, tg.seg130_111_up), nil)
			},
			ExpectedSegments: segfetcher.Segments{
				tg.seg120_111_up,
				tg.seg130_111_up,
			},
			ExpectedFetchReqs: nil,
		},
		"Up Core": {
			Reqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
				segfetcher.Request{SegType: Core, Src: isd1, Dst: core_110},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// no cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any())
				// no cached core segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(isd1),
					gomock.Eq(core_110), gomock.Any())
			},
			ExpectedFetchReqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
				segfetcher.Request{SegType: Core, Src: isd1, Dst: core_110},
			},
		},
		"Up(cached) Core": {
			Reqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
				segfetcher.Request{SegType: Core, Src: core_120, Dst: core_110},
				segfetcher.Request{SegType: Core, Src: core_130, Dst: core_110},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111_up, tg.seg130_111_up), nil)
				// no cached core segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_120),
					gomock.Eq(core_110), gomock.Any())
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_130),
					gomock.Eq(core_110), gomock.Any())
			},
			ExpectedSegments: segfetcher.Segments{tg.seg120_111_up, tg.seg130_111_up},
			ExpectedFetchReqs: segfetcher.Requests{
				segfetcher.Request{SegType: Core, Src: core_120, Dst: core_110},
				segfetcher.Request{SegType: Core, Src: core_130, Dst: core_110},
			},
		},
		"Up(cached) Core(cached)": {
			Reqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
				segfetcher.Request{SegType: Core, Src: core_120, Dst: core_110},
				segfetcher.Request{SegType: Core, Src: core_130, Dst: core_110},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111_up, tg.seg130_111_up), nil)
				// cached core segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_120),
					gomock.Eq(core_110), gomock.Any()).Return(futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(core_130),
					gomock.Eq(core_110), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_core},
					StartsAt: []addr.IA{core_110}, EndsAt: []addr.IA{core_120},
				})).Return(resultsFromSegs(tg.seg110_120_core), nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_core},
					StartsAt: []addr.IA{core_110}, EndsAt: []addr.IA{core_130},
				})).Return(resultsFromSegs(tg.seg110_130_core), nil)
			},
			ExpectedSegments: segfetcher.Segments{tg.seg120_111_up, tg.seg130_111_up,
				tg.seg110_120_core, tg.seg110_130_core},
			ExpectedFetchReqs: nil,
		},
		"Up down": {
			Reqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_211, Dst: isd2},
				segfetcher.Request{SegType: Core, Src: isd2, Dst: isd2},
				segfetcher.Request{SegType: Down, Src: isd2, Dst: non_core_212},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), non_core_211, isd2, gomock.Any())
				db.EXPECT().GetNextQuery(gomock.Any(), isd2, isd2, gomock.Any())
				db.EXPECT().GetNextQuery(gomock.Any(), isd2, non_core_212, gomock.Any())
			},
			ExpectedFetchReqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_211, Dst: isd2},
				segfetcher.Request{SegType: Core, Src: isd2, Dst: isd2},
				segfetcher.Request{SegType: Down, Src: isd2, Dst: non_core_212},
			},
		},
		"Up(cached) down(cached)": {
			Reqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_211, Dst: isd2},
				segfetcher.Request{SegType: Core, Src: isd2, Dst: isd2},
				segfetcher.Request{SegType: Down, Src: isd2, Dst: non_core_212},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), non_core_211, isd2, gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), isd2, isd2, gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), isd2, non_core_212, gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd2}, EndsAt: []addr.IA{non_core_211},
				})).Return(resultsFromSegs(tg.seg210_211_up), nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_core},
					StartsAt: []addr.IA{isd2}, EndsAt: []addr.IA{isd2},
				}))
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_down},
					StartsAt: []addr.IA{isd2}, EndsAt: []addr.IA{non_core_212},
				})).Return(resultsFromSegs(tg.seg210_212_down), nil)
			},
			ExpectedSegments:  segfetcher.Segments{tg.seg210_211_up, tg.seg210_212_down},
			ExpectedFetchReqs: nil,
		},
		"Up Core Down": {
			Reqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
				segfetcher.Request{SegType: Core, Src: isd1, Dst: isd2},
				segfetcher.Request{SegType: Down, Src: isd2, Dst: non_core_211},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// no cached segments
				db.EXPECT().GetNextQuery(gomock.Any(), non_core_111, isd1, gomock.Any())
				db.EXPECT().GetNextQuery(gomock.Any(), isd1, isd2, gomock.Any())
				db.EXPECT().GetNextQuery(gomock.Any(), isd2, non_core_211, gomock.Any())
			},
			ExpectedFetchReqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
				segfetcher.Request{SegType: Core, Src: isd1, Dst: isd2},
				segfetcher.Request{SegType: Down, Src: isd2, Dst: non_core_211},
			},
		},
		"Up(cached) Core Down": {
			Reqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
				segfetcher.Request{SegType: Core, Src: isd1, Dst: isd2},
				segfetcher.Request{SegType: Down, Src: isd2, Dst: non_core_211},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), non_core_111, isd1, gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111_up, tg.seg130_111_up), nil)
				db.EXPECT().GetNextQuery(gomock.Any(), isd1, isd2, gomock.Any())
				db.EXPECT().GetNextQuery(gomock.Any(), isd2, non_core_211, gomock.Any())
			},
			ExpectedSegments: segfetcher.Segments{tg.seg120_111_up, tg.seg130_111_up},
			ExpectedFetchReqs: segfetcher.Requests{
				segfetcher.Request{SegType: Core, Src: isd1, Dst: isd2},
				segfetcher.Request{SegType: Down, Src: isd2, Dst: non_core_211},
			},
		},
		"Up(cached) Core Down(cached)": {
			Reqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_211, Dst: isd2},
				segfetcher.Request{SegType: Core, Src: isd2, Dst: isd1},
				segfetcher.Request{SegType: Down, Src: isd1, Dst: non_core_111},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), non_core_211, isd2, gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd2}, EndsAt: []addr.IA{non_core_211},
				})).Return(resultsFromSegs(tg.seg210_211_up), nil)
				db.EXPECT().GetNextQuery(gomock.Any(), isd1, non_core_111, gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_down},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111_down, tg.seg130_111_down), nil)
				db.EXPECT().GetNextQuery(gomock.Any(), isd2, isd1, gomock.Any())
			},
			ExpectedSegments: segfetcher.Segments{tg.seg210_211_up,
				tg.seg120_111_down, tg.seg130_111_down},
			ExpectedFetchReqs: segfetcher.Requests{
				segfetcher.Request{SegType: Core, Src: isd2, Dst: isd1},
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
	// tg := newTestGraph(rootCtrl)
	// futureT := time.Now().Add(2 * time.Minute)

	tests := map[string]resolverTest{
		"Up(cache-bypass) Core Down(cache-bypass)": {
			Reqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_211, Dst: isd2},
				segfetcher.Request{SegType: Core, Src: isd2, Dst: isd1},
				segfetcher.Request{SegType: Down, Src: isd1, Dst: non_core_111},
			},
			Refresh:          true,
			ExpectCalls:      func(db *mock_pathdb.MockPathDB) {},
			ExpectedSegments: nil,
			ExpectedFetchReqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_211, Dst: isd2},
				segfetcher.Request{SegType: Core, Src: isd2, Dst: isd1},
				segfetcher.Request{SegType: Down, Src: isd1, Dst: non_core_111},
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
			Reqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				// cached up segments
				db.EXPECT().GetNextQuery(gomock.Any(), gomock.Eq(non_core_111),
					gomock.Eq(isd1), gomock.Any()).Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_up},
					StartsAt: []addr.IA{isd1}, EndsAt: []addr.IA{non_core_111},
				})).Return(resultsFromSegs(tg.seg120_111_up, tg.seg130_111_up), nil)
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
			ExpectedSegments: nil,
			ExpectedFetchReqs: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_111, Dst: isd1},
			},
		},
		"Core (cached) with revocations returns full result": {
			Reqs: segfetcher.Requests{
				segfetcher.Request{SegType: Core, Src: core_210, Dst: core_110},
				segfetcher.Request{SegType: Core, Src: core_210, Dst: core_120},
				segfetcher.Request{SegType: Core, Src: core_210, Dst: core_130},
			},
			ExpectCalls: func(db *mock_pathdb.MockPathDB) {
				db.EXPECT().GetNextQuery(gomock.Any(), core_210, core_110, gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), core_210, core_120, gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().GetNextQuery(gomock.Any(), core_210, core_130, gomock.Any()).
					Return(futureT, nil)
				db.EXPECT().Get(gomock.Any(), matchers.EqParams(&query.Params{
					SegTypes: []proto.PathSegType{proto.PathSegType_core},
					StartsAt: []addr.IA{core_130}, EndsAt: []addr.IA{core_210},
				})).Return(resultsFromSegs(tg.seg210_130_core, tg.seg210_130_2_core), nil)
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
			ExpectedSegments:  segfetcher.Segments{tg.seg210_130_core, tg.seg210_130_2_core},
			ExpectedFetchReqs: nil,
		},
	}
	for name, test := range tests {
		t.Run(name, test.run)
	}
}

func resultsFromSegs(segs ...*seg.Meta) query.Results {
	results := make(query.Results, 0, len(segs))
	for _, seg := range segs {
		results = append(results, &query.Result{
			Type:       seg.Type,
			Seg:        seg.Segment,
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

func (neverLocal) IsSegLocal(_ segfetcher.Request) bool {
	return false
}
