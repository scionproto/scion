// Copyright 2019 ETH Zurich
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

package adapter_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpath"
	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpathdb"
	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpathdb/adapter"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/pathdbtest"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/xtest/matchers"
)

var (
	owner    = addr.IA{I: 0, A: 0xff0000000330}
	end      = addr.IA{I: 5, A: 0xff0000000440}
	suffix   = uint16(1337)
	ifs      = []uint64{0, 5, 2, 3, 6, 3, 1, 0}
	groupIds = hiddenpath.GroupIdSet{
		hiddenpath.GroupId{}:               struct{}{},
		{OwnerAS: owner.A, Suffix: suffix}: struct{}{},
	}
	hpCfgIDs = []*query.HPCfgID{
		&query.NullHpCfgID,
		{
			IA: owner,
			ID: uint64(suffix),
		},
	}
	params = &hiddenpathdb.Params{
		EndsAt:   end,
		GroupIds: groupIds,
	}
	queryParams = &query.Params{
		EndsAt:   []addr.IA{end},
		HpCfgIDs: hpCfgIDs,
	}
)

func TestAdapter(t *testing.T) {
	tests := map[string]func(*testing.T, context.Context, *mock_pathdb.MockPathDB,
		*gomock.Controller){

		"Get with params": func(t *testing.T, ctx context.Context, pdb *mock_pathdb.MockPathDB,
			_ *gomock.Controller) {

			pdb.EXPECT().Get(ctx, matchers.EqParams(queryParams))
			adapter.New(pdb).Get(ctx, params)
		},
		"Get no params": func(t *testing.T, ctx context.Context, pdb *mock_pathdb.MockPathDB,
			_ *gomock.Controller) {

			pdb.EXPECT().Get(ctx, nil)
			adapter.New(pdb).Get(ctx, nil)
		},
		"Insert": func(t *testing.T, ctx context.Context, pdb *mock_pathdb.MockPathDB,
			ctrl *gomock.Controller) {

			pseg, _ := pathdbtest.AllocPathSegment(t, ctrl, ifs, uint32(10))
			pdb.EXPECT().InsertWithHPCfgIDs(ctx, getSeg(pseg), matchers.EqHPCfgIDs(hpCfgIDs))
			adapter.New(pdb).Insert(ctx, getSeg(pseg), groupIds)
		},
		"Delete with params": func(t *testing.T, ctx context.Context, pdb *mock_pathdb.MockPathDB,
			_ *gomock.Controller) {

			pdb.EXPECT().Delete(ctx, matchers.EqParams(queryParams))
			adapter.New(pdb).Delete(ctx, params)
		},
		"Delete no params": func(t *testing.T, ctx context.Context, pdb *mock_pathdb.MockPathDB,
			_ *gomock.Controller) {

			pdb.EXPECT().Delete(ctx, nil)
			adapter.New(pdb).Delete(ctx, nil)
		},
		"DeleteExpired": func(t *testing.T, ctx context.Context, pdb *mock_pathdb.MockPathDB,
			_ *gomock.Controller) {

			timeNow := time.Now()
			pdb.EXPECT().DeleteExpired(ctx, timeNow)
			adapter.New(pdb).DeleteExpired(ctx, timeNow)
		},
		"BeginTransaction": func(t *testing.T, ctx context.Context, pdb *mock_pathdb.MockPathDB,
			_ *gomock.Controller) {

			pdb.EXPECT().BeginTransaction(ctx, nil)
			adapter.New(pdb).BeginTransaction(ctx, nil)
		},
		"Close": func(t *testing.T, ctx context.Context, pdb *mock_pathdb.MockPathDB,
			_ *gomock.Controller) {
			pdb.EXPECT().Close()
			adapter.New(pdb).Close()
		},
		"Commit": func(t *testing.T, ctx context.Context, pdb *mock_pathdb.MockPathDB,
			ctrl *gomock.Controller) {

			tx := mock_pathdb.NewMockTransaction(ctrl)
			pdb.EXPECT().BeginTransaction(ctx, gomock.Any()).Return(tx, nil)
			tx.EXPECT().Commit()
			pdbTx, err := adapter.New(pdb).BeginTransaction(ctx, nil)
			require.NoError(t, err)
			pdbTx.Commit()
		},
		"Rollback": func(t *testing.T, ctx context.Context, pdb *mock_pathdb.MockPathDB,
			ctrl *gomock.Controller) {

			tx := mock_pathdb.NewMockTransaction(ctrl)
			pdb.EXPECT().BeginTransaction(ctx, gomock.Any()).Return(tx, nil)
			tx.EXPECT().Rollback()
			pdbTx, err := adapter.New(pdb).BeginTransaction(ctx, nil)
			require.NoError(t, err)
			pdbTx.Rollback()
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()
			pdb := mock_pathdb.NewMockPathDB(ctrl)
			test(t, ctx, pdb, ctrl)
		})
	}
}

func getSeg(pseg *seg.PathSegment) *seg.Meta {
	return &seg.Meta{
		Segment: pseg,
		Type:    seg.TypeDown,
	}

}
