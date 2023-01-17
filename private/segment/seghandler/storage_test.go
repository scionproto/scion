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

package seghandler_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/private/xtest/graph"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/pathdb/mock_pathdb"
	"github.com/scionproto/scion/private/segment/seghandler"
)

func TestDefaultStorageStoreSegs(t *testing.T) {
	rootCtrl := gomock.NewController(t)
	defer rootCtrl.Finish()

	tg := graph.NewDefaultGraph(rootCtrl)
	seg110To130 := tg.Beacon([]uint16{graph.If_110_X_120_A, graph.If_120_A_130_B})
	seg110To130Short := tg.Beacon([]uint16{graph.If_110_X_130_A})

	tests := map[string]struct {
		Segs           []*seg.Meta
		PathDB         func(ctrl *gomock.Controller) pathdb.DB
		ExpectedStats  seghandler.SegStats
		ErrorAssertion assert.ErrorAssertionFunc
	}{
		"Transaction creation error": {
			PathDB: func(ctrl *gomock.Controller) pathdb.DB {
				pathDB := mock_pathdb.NewMockDB(ctrl)
				pathDB.EXPECT().BeginTransaction(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("test err"))
				return pathDB
			},
			ErrorAssertion: assert.Error,
		},
		"Empty input": {
			PathDB: func(ctrl *gomock.Controller) pathdb.DB {
				pathDB := mock_pathdb.NewMockDB(ctrl)
				tx := mock_pathdb.NewMockTransaction(ctrl)
				gomock.InOrder(
					pathDB.EXPECT().BeginTransaction(gomock.Any(), gomock.Any()).
						Return(tx, nil),
					tx.EXPECT().Commit(),
				)
				return pathDB
			},
			ErrorAssertion: assert.NoError,
		},
		"Commit error": {
			PathDB: func(ctrl *gomock.Controller) pathdb.DB {
				pathDB := mock_pathdb.NewMockDB(ctrl)
				tx := mock_pathdb.NewMockTransaction(ctrl)
				gomock.InOrder(
					pathDB.EXPECT().BeginTransaction(gomock.Any(), gomock.Any()).
						Return(tx, nil),
					tx.EXPECT().Commit().Return(errors.New("test err")),
					tx.EXPECT().Rollback(),
				)
				return pathDB
			},
			ErrorAssertion: assert.Error,
		},
		"Rollback error": {
			PathDB: func(ctrl *gomock.Controller) pathdb.DB {
				pathDB := mock_pathdb.NewMockDB(ctrl)
				tx := mock_pathdb.NewMockTransaction(ctrl)
				gomock.InOrder(
					pathDB.EXPECT().BeginTransaction(gomock.Any(), gomock.Any()).
						Return(tx, nil),
					tx.EXPECT().Commit().Return(errors.New("test err")),
					tx.EXPECT().Rollback().Return(errors.New("test rollback err")),
				)
				return pathDB
			},
			ErrorAssertion: assert.Error,
		},
		"Stats correct": {
			Segs: []*seg.Meta{
				{Segment: seg110To130, Type: seg.TypeCore},
				{Segment: seg110To130Short, Type: seg.TypeCore},
			},
			PathDB: func(ctrl *gomock.Controller) pathdb.DB {
				pathDB := mock_pathdb.NewMockDB(ctrl)
				tx := mock_pathdb.NewMockTransaction(ctrl)
				gomock.InOrder(
					pathDB.EXPECT().BeginTransaction(gomock.Any(), gomock.Any()).
						Return(tx, nil),
					tx.EXPECT().Insert(gomock.Any(),
						&seg.Meta{
							Segment: seg110To130Short,
							Type:    seg.TypeCore,
						},
					).Return(pathdb.InsertStats{Updated: 1}, nil),
					tx.EXPECT().Insert(gomock.Any(),
						&seg.Meta{
							Segment: seg110To130,
							Type:    seg.TypeCore,
						},
					).Return(pathdb.InsertStats{Inserted: 1}, nil),
					tx.EXPECT().Commit(),
				)
				return pathDB
			},
			ErrorAssertion: assert.NoError,
			ExpectedStats: seghandler.SegStats{
				InsertedSegs: []string{seg110To130.GetLoggingID()},
				UpdatedSegs:  []string{seg110To130Short.GetLoggingID()},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			storage := seghandler.DefaultStorage{
				PathDB: test.PathDB(ctrl),
			}
			stats, err := storage.StoreSegs(context.Background(), test.Segs)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedStats, stats)
		})
	}
}
