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
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
)

func TestStorerGet(t *testing.T) {
	want, dbresult := createSegs()
	testCases := map[string]struct {
		inputGroups []hiddenpath.GroupID
		inputIA     addr.IA
		db          func(*gomock.Controller) pathdb.PathDB
		want        []*seg.Meta
		assertErr   assert.ErrorAssertionFunc
	}{
		"valid": {
			inputGroups: []hiddenpath.GroupID{
				{OwnerAS: xtest.MustParseAS("ff00:0:111"), Suffix: 42},
			},
			inputIA: xtest.MustParseIA("1-ff00:0:110"),
			db: func(c *gomock.Controller) pathdb.PathDB {
				ret := mock_pathdb.NewMockPathDB(c)
				ret.EXPECT().Get(gomock.Any(), &query.Params{
					EndsAt: []addr.IA{xtest.MustParseIA("1-ff00:0:110")},
					HpCfgIDs: []*query.HPCfgID{
						{IA: xtest.MustParseIA("0-ff00:0:111"), ID: 42},
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
				{OwnerAS: xtest.MustParseAS("ff00:0:111"), Suffix: 42},
			},
			inputIA: xtest.MustParseIA("1-ff00:0:110"),
			db: func(c *gomock.Controller) pathdb.PathDB {
				ret := mock_pathdb.NewMockPathDB(c)
				ret.EXPECT().Get(gomock.Any(), &query.Params{
					EndsAt: []addr.IA{xtest.MustParseIA("1-ff00:0:110")},
					HpCfgIDs: []*query.HPCfgID{
						{IA: xtest.MustParseIA("0-ff00:0:111"), ID: 42},
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
	want, _ := createSegs()
	testCases := map[string]struct {
		inputGroup hiddenpath.GroupID
		inputSegs  []*seg.Meta
		db         func(*gomock.Controller) pathdb.PathDB
		assertErr  assert.ErrorAssertionFunc
	}{
		"valid": {
			inputGroup: hiddenpath.GroupID{
				OwnerAS: xtest.MustParseAS("ff00:0:111"), Suffix: 42,
			},
			inputSegs: want,
			db: func(c *gomock.Controller) pathdb.PathDB {
				ret := mock_pathdb.NewMockPathDB(c)
				ret.EXPECT().InsertWithHPCfgIDs(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(pathdb.InsertStats{}, nil)
				return ret
			},
			assertErr: assert.NoError,
		},
		"db error": {
			inputGroup: hiddenpath.GroupID{
				OwnerAS: xtest.MustParseAS("ff00:0:111"), Suffix: 42,
			},
			inputSegs: want,
			db: func(c *gomock.Controller) pathdb.PathDB {
				ret := mock_pathdb.NewMockPathDB(c)
				ret.EXPECT().InsertWithHPCfgIDs(gomock.Any(), gomock.Any(), gomock.Any()).
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

func createSegs() ([]*seg.Meta, query.Results) {
	asEntry := seg.ASEntry{
		Local: xtest.MustParseIA("1-ff00:0:110"),
		HopEntry: seg.HopEntry{
			HopField: seg.HopField{MAC: bytes.Repeat([]byte{0x11}, 6)},
		},
	}
	ps, _ := seg.CreateSegment(time.Now(), 1337)
	ps.AddASEntry(context.Background(), asEntry, graph.NewSigner())

	ret1 := []*seg.Meta{{Type: seg.TypeDown, Segment: ps}}
	ret2 := query.Results{&query.Result{
		Type: seg.TypeDown,
		Seg:  ps,
	}}
	return ret1, ret2
}
