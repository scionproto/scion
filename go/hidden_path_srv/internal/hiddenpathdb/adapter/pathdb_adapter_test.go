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

package adapter

import (
	"context"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpathdb"
	"github.com/scionproto/scion/go/hidden_path_srv/internal/hpsegreq"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/hiddenpath"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/pathdbtest"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/proto"
)

var (
	owner    = addr.IA{I: 0, A: 0xff0000000330}
	end      = addr.IA{I: 5, A: 0xff0000000440}
	suffix   = uint16(1337)
	ifs      = []uint64{0, 5, 2, 3, 6, 3, 1, 0}
	ctx      = context.Background()
	groupIds = hpsegreq.GroupIdSet{
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

func newTestDB(t *testing.T) (*gomock.Controller,
	*PathDBAdapter, *mock_pathdb.MockPathDB) {

	ctrl := gomock.NewController(t)
	mockBackend := mock_pathdb.NewMockPathDB(ctrl)
	return ctrl, &PathDBAdapter{
		backend:    mockBackend,
		readWriter: &readWriter{mockBackend},
	}, mockBackend
}

func newTestTransaction(t *testing.T) (*gomock.Controller,
	*transaction, *mock_pathdb.MockTransaction) {

	ctrl := gomock.NewController(t)
	mockBackend := mock_pathdb.NewMockTransaction(ctrl)
	return ctrl, &transaction{
		backend:    mockBackend,
		readWriter: &readWriter{mockBackend},
	}, mockBackend
}

// TestOpenExisting tests that New does not overwrite an existing database if
// versions match.
func TestOpenExisting(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	db, tmpF := setupDB(t)
	defer os.Remove(tmpF)
	TS := uint32(10)
	pseg, _ := pathdbtest.AllocPathSegment(t, ctrl, ifs, TS)
	db.Insert(ctx, getSeg(pseg), groupIds)
	db.Close()
	// Call
	db, err := New(tmpF)
	require.NoError(t, err)
	// Test
	// Check that path segment is still there.
	res, err := db.Get(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, len(res), "Segment still exists")
}

func TestGet(t *testing.T) {
	ctrl, db, mockBackend := newTestDB(t)
	defer ctrl.Finish()
	mockBackend.EXPECT().Get(ctx, queryParams).Times(1)
	mockBackend.EXPECT().Get(ctx, nil).Times(1)
	db.Get(ctx, params)
	// handles nil params
	db.Get(ctx, nil)
}

func TestInsert(t *testing.T) {
	ctrl, db, mockBackend := newTestDB(t)
	defer ctrl.Finish()
	TS := uint32(10)
	pseg, _ := pathdbtest.AllocPathSegment(t, ctrl, ifs, TS)
	mockBackend.EXPECT().InsertWithHPCfgIDs(ctx, getSeg(pseg), hpCfgIDs).Times(1)
	db.Insert(ctx, getSeg(pseg), groupIds)
}

func TestDelete(t *testing.T) {
	ctrl, db, mockBackend := newTestDB(t)
	defer ctrl.Finish()
	mockBackend.EXPECT().Delete(ctx, queryParams).Times(1)
	mockBackend.EXPECT().Delete(ctx, nil).Times(1)
	db.Delete(ctx, params)
	// handles nil params
	db.Delete(ctx, nil)
}

func TestDeleteExpired(t *testing.T) {
	ctrl, db, mockBackend := newTestDB(t)
	defer ctrl.Finish()
	timeNow := time.Now()
	mockBackend.EXPECT().DeleteExpired(ctx, timeNow).Times(1)
	db.DeleteExpired(ctx, timeNow)
}

func TestBeginTransaction(t *testing.T) {
	ctrl, db, mockBackend := newTestDB(t)
	defer ctrl.Finish()
	mockBackend.EXPECT().BeginTransaction(ctx, nil).Times(1)
	db.BeginTransaction(ctx, nil)
}

func TestClose(t *testing.T) {
	ctrl, db, mockBackend := newTestDB(t)
	defer ctrl.Finish()
	mockBackend.EXPECT().Close().Times(1)
	db.Close()
}

func TestCommit(t *testing.T) {
	ctrl, tx, mockBackend := newTestTransaction(t)
	defer ctrl.Finish()
	mockBackend.EXPECT().Commit().Times(1)
	tx.Commit()
}

func TestRollback(t *testing.T) {
	ctrl, tx, mockBackend := newTestTransaction(t)
	defer ctrl.Finish()
	mockBackend.EXPECT().Rollback().Times(1)
	tx.Rollback()
}

func getSeg(pseg *seg.PathSegment) *seg.Meta {
	return seg.NewMeta(pseg, proto.PathSegType_down)
}

func setupDB(t *testing.T) (hiddenpathdb.HiddenPathDB, string) {
	tmpFile := tempFilename(t)
	b, err := New(tmpFile)
	require.NoError(t, err, "Failed to open DB")
	return b, tmpFile
}

func tempFilename(t *testing.T) string {
	dir, err := ioutil.TempDir("", "pathdb-sqlite")
	require.NoError(t, err)
	return path.Join(dir, t.Name())
}
