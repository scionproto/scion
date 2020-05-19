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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/revcache/memrevcache"
	"github.com/scionproto/scion/go/lib/revcache/mock_revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
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
		seg130_132: g.Beacon([]common.IFIDType{graph.If_130_A_131_X, graph.If_131_X_132_X}, false),
		seg110_130: g.Beacon([]common.IFIDType{graph.If_110_X_130_A}, false),
		seg120_210: g.Beacon([]common.IFIDType{graph.If_120_B_220_X, graph.If_220_X_210_X}, false),
		seg120_220: g.Beacon([]common.IFIDType{graph.If_120_B_220_X}, false),

		seg210_211: g.Beacon([]common.IFIDType{graph.If_210_X_211_A}, false),
		seg210_220: g.Beacon([]common.IFIDType{graph.If_210_X_220_X}, false),
		seg210_222: g.Beacon([]common.IFIDType{graph.If_210_X_211_A, graph.If_211_A_222_X}, false),

		seg220_130: g.Beacon([]common.IFIDType{graph.If_220_X_120_B, graph.If_120_A_130_B}, false),
		seg220_210: g.Beacon([]common.IFIDType{graph.If_220_X_210_X}, false),
		seg220_221: g.Beacon([]common.IFIDType{graph.If_220_X_221_X}, false),
		seg220_222: g.Beacon([]common.IFIDType{graph.If_220_X_221_X, graph.If_221_X_222_X}, false),
	}
	return tg
}

func TestFetchDB(t *testing.T) {
	Convey("FetchDB", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		g := newTestGraph(ctrl)
		mPathDB := mock_pathdb.NewMockPathDB(ctrl)
		mRevCache := mock_revcache.NewMockRevCache(ctrl)
		h := baseHandler{
			pathDB:   mPathDB,
			revCache: mRevCache,
		}
		Convey("Segment returned if not expired or revoked", func() {
			mPathDB.EXPECT().Get(gomock.Any(), gomock.Any()).Return([]*query.Result{{
				Seg: g.seg130_132,
			}}, nil)
			mRevCache.EXPECT().Get(gomock.Any(), gomock.Any()).AnyTimes()
			res, err := h.fetchSegsFromDB(context.Background(), nil)
			xtest.FailOnErr(t, err)
			SoMsg("Segments", res, ShouldResemble, []*seg.PathSegment{g.seg130_132})
		})
		Convey("No segments with on hop revocations returned", func() {
			mPathDB.EXPECT().Get(gomock.Any(), gomock.Any()).Return([]*query.Result{{
				Seg: g.seg130_132,
			}}, nil)
			mRevCache.EXPECT().Get(gomock.Any(), gomock.Any()).AnyTimes().Return(
				revcache.Revocations{
					revcache.Key{}: {}, // non empty map is enough.
				},
				nil,
			)
			res, err := h.fetchSegsFromDB(context.Background(), nil)
			xtest.FailOnErr(t, err)
			SoMsg("No segments expected", res, ShouldBeEmpty)
		})
		Convey("Error of revCache is handled", func() {
			mPathDB.EXPECT().Get(gomock.Any(), gomock.Any()).Return([]*query.Result{{
				Seg: g.seg130_132,
			}}, nil)
			expErr := serrors.New("TestError")
			mRevCache.EXPECT().Get(gomock.Any(), gomock.Any()).AnyTimes().Return(
				nil,
				expErr,
			)
			res, err := h.fetchSegsFromDB(context.Background(), nil)
			SoMsg("Error from revcache expected", err, ShouldNotBeNil)
			SoMsg("No segments expected", res, ShouldBeEmpty)
		})
		// TODO(lukedirtwalker): Test for expired segs, and revoked peer ifaces
	})
}

func TestFetchDBRetry(t *testing.T) {
	Convey("FetchDBRetry", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		g := newTestGraph(ctrl)
		Convey("Fetching stops after context is cancelled", func() {
			ctx, cancelF := context.WithCancel(context.Background())
			m := mock_pathdb.NewMockPathDB(ctrl)
			gomock.InOrder(
				m.EXPECT().Get(gomock.Any(), gomock.Any()).Times(2),
				m.EXPECT().Get(gomock.Any(), gomock.Any()).Do(
					func(context.Context, *query.Params) ([]*query.Result, error) {
						cancelF()
						return nil, nil
					}),
			)
			h := baseHandler{
				pathDB:   m,
				retryInt: 100 * time.Microsecond,
			}
			_, err := h.fetchSegsFromDBRetry(ctx, nil)
			SoMsg("Expect context err", err, ShouldEqual, ctx.Err())
		})
		Convey("Fetching stops after result is returned", func() {
			m := mock_pathdb.NewMockPathDB(ctrl)
			res := &query.Result{
				Seg: g.seg130_132,
			}
			gomock.InOrder(
				m.EXPECT().Get(gomock.Any(), gomock.Any()).Times(2),
				m.EXPECT().Get(gomock.Any(), gomock.Any()).Return([]*query.Result{res}, nil),
			)
			h := baseHandler{
				pathDB:   m,
				retryInt: 100 * time.Microsecond,
				revCache: memrevcache.New(),
			}
			_, err := h.fetchSegsFromDBRetry(context.Background(), nil)
			SoMsg("Expect no err", err, ShouldBeNil)
		})
	})
}
