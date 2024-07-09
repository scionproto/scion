// Copyright 2020 Anapaya Systems
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

package hiddenpath_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/pathdb/mock_pathdb"
	"github.com/scionproto/scion/private/pathdb/query"
)

func TestStorerGet(t *testing.T) {
	want, dbresult := createSegs(t)
	groupID := hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:111"), Suffix: 42}
	testCases := map[string]struct {
		inputGroups []hiddenpath.GroupID
		inputIA     addr.IA
		db          func(*gomock.Controller) pathdb.DB
		want        []*seg.Meta
		assertErr   assert.ErrorAssertionFunc
	}{
		"valid": {
			inputGroups: []hiddenpath.GroupID{
				groupID,
			},
			inputIA: addr.MustParseIA("1-ff00:0:110"),
			db: func(c *gomock.Controller) pathdb.DB {
				ret := mock_pathdb.NewMockDB(c)
				ret.EXPECT().Get(gomock.Any(), &query.Params{
					EndsAt: []addr.IA{addr.MustParseIA("1-ff00:0:110")},
					HPGroupIDs: []uint64{
						groupID.ToUint64(),
					},
				}).
					Return(dbresult, nil)
				return ret
			},
			want:      want,
			assertErr: assert.NoError,
		},
		"db error": {
			inputGroups: []hiddenpath.GroupID{
				groupID,
			},
			inputIA: addr.MustParseIA("1-ff00:0:110"),
			db: func(c *gomock.Controller) pathdb.DB {
				ret := mock_pathdb.NewMockDB(c)
				ret.EXPECT().Get(gomock.Any(), &query.Params{
					EndsAt: []addr.IA{addr.MustParseIA("1-ff00:0:110")},
					HPGroupIDs: []uint64{
						groupID.ToUint64(),
					},
				}).Return(nil, serrors.New("dummy-error"))
				return ret
			},
			want:      nil,
			assertErr: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			s := hiddenpath.Storer{
				DB: tc.db(ctrl),
			}
			got, err := s.Get(context.Background(), tc.inputIA, tc.inputGroups)
			tc.assertErr(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestStorerPut(t *testing.T) {
	want, _ := createSegs(t)
	testCases := map[string]struct {
		inputGroup hiddenpath.GroupID
		inputSegs  []*seg.Meta
		db         func(*gomock.Controller) pathdb.DB
		assertErr  assert.ErrorAssertionFunc
	}{
		"valid": {
			inputGroup: hiddenpath.GroupID{
				OwnerAS: addr.MustParseAS("ff00:0:111"), Suffix: 42,
			},
			inputSegs: want,
			db: func(c *gomock.Controller) pathdb.DB {
				ret := mock_pathdb.NewMockDB(c)
				ret.EXPECT().InsertWithHPGroupIDs(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(pathdb.InsertStats{}, nil)
				return ret
			},
			assertErr: assert.NoError,
		},
		"db error": {
			inputGroup: hiddenpath.GroupID{
				OwnerAS: addr.MustParseAS("ff00:0:111"), Suffix: 42,
			},
			inputSegs: want,
			db: func(c *gomock.Controller) pathdb.DB {
				ret := mock_pathdb.NewMockDB(c)
				ret.EXPECT().InsertWithHPGroupIDs(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(pathdb.InsertStats{}, serrors.New("dummy-error"))
				return ret
			},
			assertErr: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			s := hiddenpath.Storer{
				DB: tc.db(ctrl),
			}
			err := s.Put(context.Background(), tc.inputSegs, tc.inputGroup)
			tc.assertErr(t, err)
		})
	}
}

func createSegs(t *testing.T) ([]*seg.Meta, query.Results) {
	t.Helper()
	asEntry := seg.ASEntry{
		Local: addr.MustParseIA("1-ff00:0:110"),
		HopEntry: seg.HopEntry{
			HopField: seg.HopField{MAC: [path.MacLen]byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11}},
		},
	}
	ps, _ := seg.CreateSegment(time.Now(), 1337)
	require.NoError(t, ps.AddASEntry(context.Background(), asEntry, graph.NewSigner()))

	ret1 := []*seg.Meta{{Type: seg.TypeDown, Segment: ps}}
	ret2 := query.Results{&query.Result{
		Type: seg.TypeDown,
		Seg:  ps,
	}}
	return ret1, ret2
}
