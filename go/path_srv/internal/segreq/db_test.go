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

package segreq_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/path_srv/internal/segreq"
	"github.com/scionproto/scion/go/path_srv/internal/segreq/mock_segreq"
)

func TestPSPathDBGet(t *testing.T) {
	tests := map[string]struct {
		PreparePathDB func(db *mock_pathdb.MockPathDB, params *query.Params,
			cancelF context.CancelFunc)
		PrepareLocalInfo func(i *mock_segreq.MockLocalInfo, params *query.Params)
		ErrorAssertion   require.ErrorAssertionFunc
	}{
		"Immediate error": {
			PreparePathDB: func(db *mock_pathdb.MockPathDB, params *query.Params,
				cancelF context.CancelFunc) {
				db.EXPECT().Get(gomock.Any(), params).
					Return(query.Results{}, errors.New("test err"))
			},
			PrepareLocalInfo: func(i *mock_segreq.MockLocalInfo, params *query.Params) {},
			ErrorAssertion:   require.Error,
		},
		"Local with segs": {
			PreparePathDB: func(db *mock_pathdb.MockPathDB, params *query.Params,
				cancelF context.CancelFunc) {
				db.EXPECT().Get(gomock.Any(), params).
					Return(query.Results{&query.Result{}}, nil)
			},
			PrepareLocalInfo: func(i *mock_segreq.MockLocalInfo, params *query.Params) {
				i.EXPECT().IsParamsLocal(params).Return(true)
			},
			ErrorAssertion: require.NoError,
		},
		"Context cancel after second try": {
			PreparePathDB: func(db *mock_pathdb.MockPathDB, params *query.Params,
				cancelF context.CancelFunc) {
				call1 := db.EXPECT().Get(gomock.Any(), params).Return(query.Results{}, nil)
				call2 := db.EXPECT().Get(gomock.Any(), params).Return(query.Results{}, nil).
					After(call1)
				db.EXPECT().Get(gomock.Any(), params).
					DoAndReturn(func(_ context.Context, _ *query.Params) (query.Results, error) {
						cancelF()
						return query.Results{}, nil
					}).After(call2)
			},
			PrepareLocalInfo: func(i *mock_segreq.MockLocalInfo, params *query.Params) {
				i.EXPECT().IsParamsLocal(params).Return(true)
			},
			ErrorAssertion: require.Error,
		},
		"Result after second try": {
			PreparePathDB: func(db *mock_pathdb.MockPathDB, params *query.Params,
				cancelF context.CancelFunc) {
				call1 := db.EXPECT().Get(gomock.Any(), params).Return(query.Results{}, nil)
				call2 := db.EXPECT().Get(gomock.Any(), params).Return(query.Results{}, nil).
					After(call1)
				db.EXPECT().Get(gomock.Any(), params).
					DoAndReturn(func(_ context.Context, _ *query.Params) (query.Results, error) {
						return query.Results{&query.Result{}}, nil
					}).After(call2)
			},
			PrepareLocalInfo: func(i *mock_segreq.MockLocalInfo, params *query.Params) {
				i.EXPECT().IsParamsLocal(params).Return(true)
			},
			ErrorAssertion: require.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			pdb := mock_pathdb.NewMockPathDB(ctrl)
			li := mock_segreq.NewMockLocalInfo(ctrl)
			params := &query.Params{EndsAt: []addr.IA{xtest.MustParseIA("1-0")}}
			ctx, cancelF := context.WithCancel(context.Background())
			defer cancelF()
			test.PreparePathDB(pdb, params, cancelF)
			test.PrepareLocalInfo(li, params)
			db := &segreq.PathDB{
				PathDB:     pdb,
				LocalInfo:  li,
				RetrySleep: time.Microsecond,
			}
			_, err := db.Get(ctx, params)
			test.ErrorAssertion(t, err)
		})
	}
}

func TestPSPathDBGetNextQuery(t *testing.T) {
	tests := map[string]struct {
		Src                     addr.IA
		Dst                     addr.IA
		PreparePathDB           func(db *mock_pathdb.MockPathDB, src, dst addr.IA)
		PrepareLocalInfo        func(i *mock_segreq.MockLocalInfo, src, dst addr.IA)
		ErrorAssertion          require.ErrorAssertionFunc
		AssertNextQueryAfterNow assert.BoolAssertionFunc
	}{
		"LocalInfo error": {
			Src:           xtest.MustParseIA("1-ff00:0:111"),
			Dst:           xtest.MustParseIA("1-ff00:0:120"),
			PreparePathDB: func(db *mock_pathdb.MockPathDB, src, dst addr.IA) {},
			PrepareLocalInfo: func(i *mock_segreq.MockLocalInfo, src, dst addr.IA) {
				i.EXPECT().IsSegLocal(gomock.Any(), src, dst).
					Return(false, errors.New("test err"))
			},
			ErrorAssertion:          require.Error,
			AssertNextQueryAfterNow: assert.False,
		},
		"Is Local": {
			Src:           xtest.MustParseIA("1-ff00:0:111"),
			Dst:           xtest.MustParseIA("1-ff00:0:120"),
			PreparePathDB: func(db *mock_pathdb.MockPathDB, src, dst addr.IA) {},
			PrepareLocalInfo: func(i *mock_segreq.MockLocalInfo, src, dst addr.IA) {
				i.EXPECT().IsSegLocal(gomock.Any(), src, dst).
					Return(true, nil)
			},
			ErrorAssertion:          require.NoError,
			AssertNextQueryAfterNow: assert.True,
		},
		"Non local": {
			Src: xtest.MustParseIA("1-ff00:0:111"),
			Dst: xtest.MustParseIA("1-ff00:0:120"),
			PreparePathDB: func(db *mock_pathdb.MockPathDB, src, dst addr.IA) {
				db.EXPECT().GetNextQuery(gomock.Any(), src, dst, gomock.Any()).
					Return(time.Now().Add(time.Hour), nil)
			},
			PrepareLocalInfo: func(i *mock_segreq.MockLocalInfo, src, dst addr.IA) {
				i.EXPECT().IsSegLocal(gomock.Any(), src, dst).
					Return(false, nil)
			},
			ErrorAssertion:          require.NoError,
			AssertNextQueryAfterNow: assert.True,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			pdb := mock_pathdb.NewMockPathDB(ctrl)
			li := mock_segreq.NewMockLocalInfo(ctrl)
			test.PreparePathDB(pdb, test.Src, test.Dst)
			test.PrepareLocalInfo(li, test.Src, test.Dst)
			db := &segreq.PathDB{
				PathDB:    pdb,
				LocalInfo: li,
			}
			nq, err := db.GetNextQuery(context.Background(), test.Src, test.Dst, nil)
			test.ErrorAssertion(t, err)
			test.AssertNextQueryAfterNow(t, nq.After(time.Now()))
		})
	}
}
