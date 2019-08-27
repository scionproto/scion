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

	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/proto"
)

func TestNextQueryCleaner(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	g := newTestGraph(ctrl)
	ctx := context.Background()

	pdb := mock_pathdb.NewMockPathDB(ctrl)
	tx := mock_pathdb.NewMockTransaction(ctrl)
	results := resultsFromSegs(g.seg210_130, g.seg210_130_2)
	for i := range results {
		results[i].Type = proto.PathSegType_core
	}
	tx.EXPECT().Get(ctx, gomock.Any()).Return(results, nil)
	tx.EXPECT().DeleteNQ(ctx, core_130, core_210, nil)
	tx.EXPECT().Commit()
	tx.EXPECT().Rollback()
	pdb.EXPECT().BeginTransaction(ctx, gomock.Any()).Return(tx, nil)

	cleaner := segfetcher.NextQueryCleaner{PathDB: pdb}
	cleaner.ResetQueryCache(ctx, &path_mgmt.RevInfo{
		IfID:     graph.If_110_X_130_A,
		RawIsdas: core_110.IAInt(),
	})
}

func TestDeleteNextQueryEntries(t *testing.T) {
	rootCtrl := gomock.NewController(t)
	defer rootCtrl.Finish()
	g := newTestGraph(rootCtrl)

	tests := map[string]struct {
		Results     query.Results
		ExpectCalls func(context.Context, *mock_pathdb.MockTransaction)
	}{
		"Empty results": {
			ExpectCalls: func(ctx context.Context, tx *mock_pathdb.MockTransaction) {},
		},
		"Down segments grouped": {
			Results: query.Results{
				{Seg: g.seg120_111, Type: proto.PathSegType_down},
				{Seg: g.seg130_111, Type: proto.PathSegType_down},
			},
			ExpectCalls: func(ctx context.Context, tx *mock_pathdb.MockTransaction) {
				tx.EXPECT().DeleteNQ(ctx, addr.IA{I: 1}, non_core_111, nil)
			},
		},
		"Up segments grouped": {
			Results: query.Results{
				{Seg: g.seg120_111, Type: proto.PathSegType_up},
				{Seg: g.seg130_111, Type: proto.PathSegType_up},
			},
			ExpectCalls: func(ctx context.Context, tx *mock_pathdb.MockTransaction) {
				tx.EXPECT().DeleteNQ(ctx, non_core_111, addr.IA{I: 1}, nil)
			},
		},
		"Mixed input": {
			Results: query.Results{
				{Seg: g.seg120_111, Type: proto.PathSegType_down},
				{Seg: g.seg130_111, Type: proto.PathSegType_down},
				{Seg: g.seg210_130, Type: proto.PathSegType_core},
				{Seg: g.seg120_111, Type: proto.PathSegType_up},
				{Seg: g.seg130_111, Type: proto.PathSegType_up},
			},
			ExpectCalls: func(ctx context.Context, tx *mock_pathdb.MockTransaction) {
				tx.EXPECT().DeleteNQ(ctx, addr.IA{I: 1}, non_core_111, nil)
				tx.EXPECT().DeleteNQ(ctx, non_core_111, addr.IA{I: 1}, nil)
				tx.EXPECT().DeleteNQ(ctx, core_130, core_210, nil)
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()

			tx := mock_pathdb.NewMockTransaction(ctrl)
			test.ExpectCalls(ctx, tx)
			segfetcher.DeleteNextQueryEntries(ctx, tx, test.Results)
		})
	}
}
