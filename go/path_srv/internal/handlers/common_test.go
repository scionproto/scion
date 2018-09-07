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

	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache/memrevcache"
)

func Test_FetchDBRetry(t *testing.T) {
	Convey("FetchDBRetry", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
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
				retryInt: time.Microsecond,
			}
			_, err := h.fetchSegsFromDBRetry(ctx, nil)
			SoMsg("Expect context err", err, ShouldEqual, ctx.Err())
		})
		Convey("Fetching stops after result is returned", func() {
			m := mock_pathdb.NewMockPathDB(ctrl)
			res := &query.Result{
				Seg: seg130_132,
			}
			gomock.InOrder(
				m.EXPECT().Get(gomock.Any(), gomock.Any()).Times(2),
				m.EXPECT().Get(gomock.Any(), gomock.Any()).Return([]*query.Result{res}, nil),
			)
			h := baseHandler{
				pathDB:   m,
				retryInt: time.Microsecond,
				revCache: memrevcache.New(time.Second, time.Second),
			}
			_, err := h.fetchSegsFromDBRetry(context.Background(), nil)
			SoMsg("Expect no err", err, ShouldBeNil)
		})
	})
}
