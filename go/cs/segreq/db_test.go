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

	"github.com/scionproto/scion/go/cs/segreq"
	"github.com/scionproto/scion/go/cs/segreq/mock_segreq"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
	"github.com/scionproto/scion/go/lib/xtest"
)

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
