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

package infra_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/proto"
)

var _ infra.ResourceHealth = (*mockResource)(nil)

type mockResource struct {
	name    string
	healthy bool
}

func (r *mockResource) Name() string {
	return r.name
}

func (r *mockResource) IsHealthy() bool {
	return r.healthy
}

func TestResourceHealth(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	Convey("Unhealthy resource results in error replied", t, func() {
		handler := infra.HandlerFunc(func(r *infra.Request) *infra.HandlerResult {
			return nil
		})
		rHandler := infra.NewResourceAwareHandler(handler,
			&mockResource{name: "tstFail", healthy: false})
		rwMock := mock_infra.NewMockResponseWriter(ctrl)
		ctx := infra.NewContextWithResponseWriter(context.Background(), rwMock)
		rwMock.EXPECT().SendAckReply(gomock.Eq(ctx), gomock.Eq(&ack.Ack{
			Err:     proto.Ack_ErrCode_reject,
			ErrDesc: "Resource tstFail not healthy",
		}))
		req := infra.NewRequest(ctx, nil, nil, nil, 1)
		rHandler.Handle(req)
	})
}
