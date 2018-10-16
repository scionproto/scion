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
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestDedupe(t *testing.T) {
	Convey("getSegsFromNetwork should dedupe", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		msger := mock_infra.NewMockMessenger(ctrl)
		ireq := &infra.Request{
			Logger: log.Root(),
		}
		h := &segReqHandler{
			baseHandler: newBaseHandler(ireq, HandlerArgs{}),
			segsDeduper: NewDeduper(msger),
		}
		reply := &path_mgmt.SegReply{}
		msger.EXPECT().GetSegs(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, _ *path_mgmt.SegReq, _ net.Addr,
				_ uint64) (*path_mgmt.SegReply, error) {

				time.Sleep(20 * time.Millisecond)
				return reply, nil
			},
		)
		req := &path_mgmt.SegReq{
			RawSrcIA: xtest.MustParseIA("1-ff00:0:110").IAInt(),
			RawDstIA: xtest.MustParseIA("1-ff00:0:211").IAInt(),
		}
		req2 := &path_mgmt.SegReq{
			RawSrcIA: req.RawSrcIA,
			RawDstIA: req.RawDstIA,
		}
		Convey("Parallel", xtest.Parallel(func(sc *xtest.SC) {
			r, err := h.getSegsFromNetwork(ctx, req, nil, 1)
			sc.SoMsg("Should be no error", err, ShouldBeNil)
			sc.SoMsg("Should return single reply", r, ShouldEqual, reply)
		}, func(sc *xtest.SC) {
			r, err := h.getSegsFromNetwork(ctx, req2, nil, 2)
			sc.SoMsg("Should be no error", err, ShouldBeNil)
			sc.SoMsg("Should return single reply", r, ShouldEqual, reply)
		}))
	})
}
