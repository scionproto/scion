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

package hpcfgreq_test

import (
	"context"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpath"
	"github.com/scionproto/scion/go/hidden_path_srv/internal/hpcfgreq"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/matchers"
	"github.com/scionproto/scion/go/proto"
)

var (
	ia110 = xtest.MustParseIA("1-ff00:0:110")
	ia111 = xtest.MustParseIA("1-ff00:0:111")
	as110 = ia110.A
	as111 = ia111.A
)

var group1 = &hiddenpath.Group{
	Id: hiddenpath.GroupId{
		OwnerAS: as110,
		Suffix:  0x69b5,
	},
	Version: 1,
	Owner:   ia110,
}

var group2 = &hiddenpath.Group{
	Id: hiddenpath.GroupId{
		OwnerAS: as111,
		Suffix:  0xabcd,
	},
	Version: 1,
	Owner:   ia111,
	Writers: []addr.IA{ia110},
}

var group3 = &hiddenpath.Group{
	Id: hiddenpath.GroupId{
		OwnerAS: as111,
		Suffix:  0xacdc,
	},
	Version: 1,
	Owner:   ia111,
	Readers: []addr.IA{ia110},
}
var group4 = &hiddenpath.Group{
	Id: hiddenpath.GroupId{
		OwnerAS: as111,
		Suffix:  0xaaaa,
	},
	Version:    1,
	Owner:      ia111,
	Registries: []addr.IA{ia110},
}

func TestCfgReq(t *testing.T) {
	log.Discard()
	tests := map[string]func(*testing.T, context.Context, infra.Handler,
		*mock_infra.MockResponseWriter){

		"valid request": func(t *testing.T, ctx context.Context,
			handler infra.Handler, rw *mock_infra.MockResponseWriter) {
			msg := &path_mgmt.HPCfgReq{
				ChangedSince: 0,
			}
			peer := &snet.UDPAddr{IA: ia110}
			req := infra.NewRequest(ctx, msg, nil, peer, 0)
			reply := &path_mgmt.HPCfgReply{
				Cfgs: []*path_mgmt.HPCfg{group1.ToMsg(), group2.ToMsg(), group3.ToMsg()},
			}

			rw.EXPECT().SendHPCfgReply(gomock.Any(), reply)
			res := handler.Handle(req)
			assert.Equal(t, infra.MetricsResultOk, res)
		},
		"wrong message type": func(t *testing.T, ctx context.Context,
			handler infra.Handler, _ *mock_infra.MockResponseWriter) {

			req := infra.NewRequest(ctx, &path_mgmt.HPSegReq{}, nil, nil, 0)
			res := handler.Handle(req)
			assert.Equal(t, infra.MetricsErrInternal, res)
		},
		"no messenger": func(t *testing.T, ctx context.Context,
			handler infra.Handler, _ *mock_infra.MockResponseWriter) {

			req := infra.NewRequest(context.Background(),
				&path_mgmt.HPCfgReq{}, nil, nil, 0)
			res := handler.Handle(req)
			assert.Equal(t, infra.MetricsErrInternal, res)
		},
		"invalid peer address type": func(t *testing.T, ctx context.Context,
			handler infra.Handler, rw *mock_infra.MockResponseWriter) {

			msg := &path_mgmt.HPCfgReq{}
			peer := &net.IPNet{}
			req := infra.NewRequest(ctx, msg, nil, peer, 0)
			ack := ack.Ack{
				Err:     proto.Ack_ErrCode_reject,
				ErrDesc: messenger.AckRejectFailedToParse,
			}
			rw.EXPECT().SendAckReply(gomock.Any(), &matchers.AckMsg{Ack: ack})
			res := handler.Handle(req)
			assert.Equal(t, infra.MetricsErrInvalid, res)
		},
		"non-local request": func(t *testing.T, ctx context.Context,
			handler infra.Handler, rw *mock_infra.MockResponseWriter) {

			msg := &path_mgmt.HPCfgReq{
				ChangedSince: 0,
			}
			peer := &snet.UDPAddr{IA: ia111}
			req := infra.NewRequest(ctx, msg, nil, peer, 0)
			ack := ack.Ack{
				Err:     proto.Ack_ErrCode_reject,
				ErrDesc: messenger.AckRejectFailedToVerify,
			}
			rw.EXPECT().SendAckReply(gomock.Any(), &matchers.AckMsg{Ack: ack})
			res := handler.Handle(req)
			assert.Equal(t, infra.MetricsErrInvalid, res)
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			rw := mock_infra.NewMockResponseWriter(ctrl)
			ctx := infra.NewContextWithResponseWriter(
				context.Background(), rw)
			handler := hpcfgreq.NewHandler(
				[]*hiddenpath.Group{group1, group2, group3, group4},
				ia110,
			)
			test(t, ctx, handler, rw)
		})
	}
}
