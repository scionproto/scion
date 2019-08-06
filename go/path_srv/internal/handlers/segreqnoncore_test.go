// Copyright 2018 Anapaya Systems
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

package handlers

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	pathdbbe "github.com/scionproto/scion/go/lib/pathdb/sqlite"
	"github.com/scionproto/scion/go/lib/revcache/memrevcache"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/path_srv/internal/config"
	"github.com/scionproto/scion/go/proto"
)

var (
	timeout = 100 * time.Millisecond

	core1_110 = xtest.MustParseIA("1-ff00:0:110")
	core1_130 = xtest.MustParseIA("1-ff00:0:130")
	core1_120 = xtest.MustParseIA("1-ff00:0:120")
	as1_132   = xtest.MustParseIA("1-ff00:0:132")

	core2_210 = xtest.MustParseIA("2-ff00:0:210")
	as2_211   = xtest.MustParseIA("2-ff00:0:211")
	core2_220 = xtest.MustParseIA("2-ff00:0:220")
	as2_221   = xtest.MustParseIA("2-ff00:0:221")
	as2_222   = xtest.MustParseIA("2-ff00:0:222")

	topoFiles = map[addr.IA]string{
		as1_132: "testdata/topology_as1_132.json",
		as2_211: "testdata/topology_as2_211.json",
		as2_222: "testdata/topology_as2_222.json",
	}
	cores = map[addr.ISD][]addr.IA{
		1: {core1_110, core1_120, core1_130},
		2: {core2_210, core2_220},
	}
)

type testGraph struct {
	g *graph.Graph

	seg130_132 *seg.PathSegment
	seg110_130 *seg.PathSegment
	seg120_210 *seg.PathSegment
	seg120_220 *seg.PathSegment

	seg210_211 *seg.PathSegment
	seg210_220 *seg.PathSegment
	seg210_222 *seg.PathSegment

	seg220_130 *seg.PathSegment
	seg220_210 *seg.PathSegment
	seg220_221 *seg.PathSegment
	seg220_222 *seg.PathSegment
}

func newTestGraph(ctrl *gomock.Controller) *testGraph {
	g := graph.NewDefaultGraph(ctrl)

	tg := &testGraph{
		seg130_132: g.Beacon([]common.IFIDType{graph.If_130_A_131_X, graph.If_131_X_132_X}),
		seg110_130: g.Beacon([]common.IFIDType{graph.If_110_X_130_A}),
		seg120_210: g.Beacon([]common.IFIDType{graph.If_120_B_220_X, graph.If_220_X_210_X}),
		seg120_220: g.Beacon([]common.IFIDType{graph.If_120_B_220_X}),

		seg210_211: g.Beacon([]common.IFIDType{graph.If_210_X_211_A}),
		seg210_220: g.Beacon([]common.IFIDType{graph.If_210_X_220_X}),
		seg210_222: g.Beacon([]common.IFIDType{graph.If_210_X_211_A, graph.If_211_A_222_X}),

		seg220_130: g.Beacon([]common.IFIDType{graph.If_220_X_120_B, graph.If_120_A_130_B}),
		seg220_210: g.Beacon([]common.IFIDType{graph.If_220_X_210_X}),
		seg220_221: g.Beacon([]common.IFIDType{graph.If_220_X_221_X}),
		seg220_222: g.Beacon([]common.IFIDType{graph.If_220_X_221_X, graph.If_221_X_222_X}),
	}
	return tg
}

type testCase struct {
	SrcIA     addr.IA
	DstIA     addr.IA
	Ups       []*seg.PathSegment
	Cores     []*seg.PathSegment
	Downs     []*seg.PathSegment
	Expected  []*seg.Meta
	CacheOnly bool
}

func setupDB(t *testing.T, tc testCase) pathdb.PathDB {
	db, err := pathdbbe.New(":memory:")
	xtest.FailOnErr(t, err)
	insertSegs(t, db, tc.Ups, proto.PathSegType_up)
	insertSegs(t, db, tc.Cores, proto.PathSegType_core)
	insertSegs(t, db, tc.Downs, proto.PathSegType_down)
	return db
}

func insertSegs(t *testing.T, pathDB pathdb.PathDB, segs []*seg.PathSegment, st proto.PathSegType) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	for _, s := range segs {
		err := s.Validate(seg.ValidateSegment)
		xtest.FailOnErr(t, err)
		_, err = pathDB.Insert(ctx, seg.NewMeta(s, st))
		xtest.FailOnErr(t, err)
	}
}

var _ gomock.Matcher = (*replyMatcher)(nil)

type replyMatcher struct {
	reply *path_mgmt.SegReply
}

func (r *replyMatcher) Matches(o interface{}) bool {
	segReply, ok := o.(*path_mgmt.SegReply)
	if !ok {
		return false
	}
	if segReply.Recs != nil {
		// Init the id field, so that deep equal works.
		for _, sm := range segReply.Recs.Recs {
			sm.Segment.ID()
			sm.Segment.FullId()
		}
		sort.Slice(segReply.Recs.Recs, func(i, j int) bool {
			return segReply.Recs.Recs[i].Segment.GetLoggingID() <
				segReply.Recs.Recs[j].Segment.GetLoggingID()
		})
	}
	return reflect.DeepEqual(r.reply, segReply)
}

func (r *replyMatcher) String() string {
	return fmt.Sprintf("Matches Reply: %v", r.reply)
}

func matchesSegsAndReq(req *path_mgmt.SegReq, segs []*seg.Meta) *replyMatcher {
	var recs *path_mgmt.SegRecs
	if segs != nil {
		recs = &path_mgmt.SegRecs{
			Recs:      segs,
			SRevInfos: []*path_mgmt.SignedRevInfo{},
		}
		sort.Slice(recs.Recs, func(i, j int) bool {
			return recs.Recs[i].Segment.GetLoggingID() < recs.Recs[j].Segment.GetLoggingID()
		})
	}
	return &replyMatcher{
		reply: &path_mgmt.SegReply{
			Req:  req,
			Recs: recs,
		},
	}
}

func expectedSegs(ups, cores, downs []*seg.PathSegment) []*seg.Meta {
	e := make([]*seg.Meta, 0, len(ups)+len(cores)+len(downs))
	for _, u := range ups {
		e = append(e, seg.NewMeta(u, proto.PathSegType_up))
	}
	for _, c := range cores {
		e = append(e, seg.NewMeta(c, proto.PathSegType_core))
	}
	for _, d := range downs {
		e = append(e, seg.NewMeta(d, proto.PathSegType_down))
	}
	return e
}

func TestSegReqLocal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	g := newTestGraph(ctrl)
	log.SetupLogConsole("debug")
	tests := map[string]testCase{
		"CoreDST: Single up, dst: core local": {
			SrcIA: as1_132,
			DstIA: core1_110,
			Ups:   []*seg.PathSegment{g.seg130_132},
			Cores: []*seg.PathSegment{g.seg110_130},
			Expected: expectedSegs([]*seg.PathSegment{g.seg130_132},
				[]*seg.PathSegment{g.seg110_130}, nil),
			CacheOnly: true,
		},
		"CoreDST: Single up, dst: core remote": {
			SrcIA: as1_132,
			DstIA: core2_220,
			Ups:   []*seg.PathSegment{g.seg130_132},
			Cores: []*seg.PathSegment{g.seg110_130, g.seg220_130},
			Expected: expectedSegs([]*seg.PathSegment{g.seg130_132},
				[]*seg.PathSegment{g.seg220_130}, nil),
			CacheOnly: true,
		},
		"CoreDST: No Up, single core, local": {
			SrcIA:     as1_132,
			DstIA:     core1_110,
			Cores:     []*seg.PathSegment{g.seg110_130},
			Expected:  nil,
			CacheOnly: true,
		},
		"CoreDST: Multi up, single core": {
			SrcIA: as2_222,
			DstIA: core1_120,
			Ups:   []*seg.PathSegment{g.seg210_222, g.seg220_222},
			Cores: []*seg.PathSegment{g.seg120_220},
			Expected: expectedSegs([]*seg.PathSegment{g.seg220_222},
				[]*seg.PathSegment{g.seg120_220}, nil),
			CacheOnly: true,
		},
		"CoreDST: Multi up multi core": {
			SrcIA: as2_222,
			DstIA: core1_120,
			Ups:   []*seg.PathSegment{g.seg210_222, g.seg220_222},
			Cores: []*seg.PathSegment{g.seg120_220, g.seg120_210},
			Expected: expectedSegs([]*seg.PathSegment{g.seg210_222, g.seg220_222},
				[]*seg.PathSegment{g.seg120_210, g.seg120_220}, nil),
			CacheOnly: true,
		},
		"NonCoreDST: Single up, no core, single down": {
			SrcIA:     as2_222,
			DstIA:     as2_211,
			Ups:       []*seg.PathSegment{g.seg220_222},
			Downs:     []*seg.PathSegment{g.seg210_211},
			Expected:  expectedSegs(nil, nil, nil),
			CacheOnly: true,
		},
		"NonCoreDst: Single up, core, down": {
			SrcIA: as2_222,
			DstIA: as2_211,
			Ups:   []*seg.PathSegment{g.seg220_222},
			Cores: []*seg.PathSegment{g.seg210_220},
			Downs: []*seg.PathSegment{g.seg210_211},
			Expected: expectedSegs([]*seg.PathSegment{g.seg220_222},
				[]*seg.PathSegment{g.seg210_220}, []*seg.PathSegment{g.seg210_211}),
			CacheOnly: true,
		},
		"NonCoreDst: On up path dst": {
			SrcIA: as2_222,
			DstIA: as2_221,
			Ups:   []*seg.PathSegment{g.seg220_222},
			Downs: []*seg.PathSegment{g.seg220_221},
			Expected: expectedSegs([]*seg.PathSegment{g.seg220_222}, nil,
				[]*seg.PathSegment{g.seg220_221}),
			CacheOnly: true,
		},
		"NonCoreDst: Path with shortcut": {
			SrcIA: as2_222,
			DstIA: as2_211,
			Ups:   []*seg.PathSegment{g.seg220_222},
			Cores: []*seg.PathSegment{g.seg210_220},
			Downs: []*seg.PathSegment{g.seg210_211},
			Expected: expectedSegs([]*seg.PathSegment{g.seg220_222},
				[]*seg.PathSegment{g.seg210_220}, []*seg.PathSegment{g.seg210_211}),
			CacheOnly: true,
		},
		"NonCoreDst: Path through same core and different": {
			SrcIA: as2_211,
			DstIA: as2_222,
			Ups:   []*seg.PathSegment{g.seg210_211},
			Cores: []*seg.PathSegment{g.seg220_210},
			Downs: []*seg.PathSegment{g.seg210_222, g.seg220_222},
			Expected: expectedSegs([]*seg.PathSegment{g.seg210_211},
				[]*seg.PathSegment{g.seg220_210}, []*seg.PathSegment{g.seg210_222, g.seg220_222}),
			CacheOnly: true,
		},
		"ISD-local wildcard should return up segments only": {
			SrcIA:     as2_222,
			DstIA:     addr.IA{I: 2},
			Ups:       []*seg.PathSegment{g.seg210_222, g.seg220_222},
			Expected:  expectedSegs([]*seg.PathSegment{g.seg210_222, g.seg220_222}, nil, nil),
			CacheOnly: false,
		},
		// TODO(lukedirtwalker): add tests with revocations.
		// TODO(lukedirtwalker): add tests with expired segs.
		// TODO(lukedirtwalker): add test with too many segments to test pruning.
	}
	var m coreOpsMatcher
	inspector := mock_infra.NewMockASInspector(ctrl)
	inspector.EXPECT().ByAttributes(gomock.Any(), gomock.Any(), m).DoAndReturn(
		func(_ context.Context, isd addr.ISD, _ infra.ASInspectorOpts) ([]addr.IA, error) {
			return cores[isd], nil
		},
	).AnyTimes()
	inspector.EXPECT().HasAttributes(gomock.Any(), gomock.Any(), m).DoAndReturn(
		func(_ context.Context, ia addr.IA, _ infra.ASInspectorOpts) (bool, error) {
			for _, isd := range cores {
				for _, core := range isd {
					if ia.Equal(core) {
						return true, nil
					}
				}
			}
			return false, nil
		},
	).AnyTimes()
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			db := setupDB(t, test)
			segReq := &path_mgmt.SegReq{
				RawSrcIA: test.SrcIA.IAInt(),
				RawDstIA: test.DstIA.IAInt(),
				Flags: path_mgmt.SegReqFlags{
					CacheOnly: test.CacheOnly,
				},
			}
			msger := mock_infra.NewMockMessenger(ctrl)
			rw := mock_infra.NewMockResponseWriter(ctrl)
			req := infra.NewRequest(
				infra.NewContextWithResponseWriter(context.Background(), rw),
				segReq,
				nil,
				&snet.Addr{IA: addr.IA{}},
				scrypto.RandUint64(),
			)
			args := HandlerArgs{
				PathDB:        db,
				RevCache:      memrevcache.New(),
				ASInspector:   inspector,
				QueryInterval: config.DefaultQueryInterval,
				IA:            test.SrcIA,
				TopoProvider:  xtest.TopoProviderFromFile(t, topoFiles[test.SrcIA]),
			}
			deduper := NewGetSegsDeduper(msger)
			h := NewSegReqNonCoreHandler(args, deduper)
			rw.EXPECT().SendSegReply(gomock.Any(), matchesSegsAndReq(segReq, test.Expected))
			h.Handle(req)
		})
	}
}

var _ gomock.Matcher = coreOpsMatcher{}

type coreOpsMatcher struct{}

// Matches returns whether the core AS attribute is requested.
func (m coreOpsMatcher) Matches(x interface{}) bool {
	opts, ok := x.(infra.ASInspectorOpts)
	if !ok {
		return false
	}
	return cmp.Equal(opts.RequiredAttributes, []infra.Attribute{infra.Core})
}

func (m coreOpsMatcher) String() string {
	return fmt.Sprintf("is core opts")
}
