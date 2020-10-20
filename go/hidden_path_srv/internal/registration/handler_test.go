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

package registration_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/hidden_path_srv/internal/registration"
	"github.com/scionproto/scion/go/hidden_path_srv/internal/registration/mock_registration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler/mock_seghandler"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest/matchers"
	"github.com/scionproto/scion/go/proto"
)

func TestSegReg(t *testing.T) {
	log.Discard()
	newTestGraph(t, gomock.NewController(t))
	tests := map[string]func(*testing.T, context.Context, infra.Handler, *mocks){
		"valid request": func(t *testing.T, ctx context.Context, handler infra.Handler, m *mocks) {
			msg := &path_mgmt.HPSegReg{
				HPSegRecs: &path_mgmt.HPSegRecs{
					GroupId: group.Id.ToMsg(),
					Recs:    []*seg.Meta{seg110_133},
				},
			}
			peer := &snet.UDPAddr{IA: addr.IA{}}
			req := infra.NewRequest(ctx, msg, nil, peer, 0)
			ack := ack.Ack{
				Err:     proto.Ack_ErrCode_ok,
				ErrDesc: "",
			}
			segments := seghandler.Segments{
				Segs:      msg.HPSegRecs.Recs,
				HPGroupID: group.Id,
			}
			m.validator.EXPECT().Validate(msg, peer.IA).Return(nil)
			m.verifier.EXPECT().Verify(gomock.Any(), segments, peer)
			m.rw.EXPECT().SendAckReply(gomock.Any(), &matchers.AckMsg{Ack: ack})
			res := handler.Handle(req)
			assert.Equal(t, infra.MetricsResultOk, res)
		},
		"wrong message type": func(t *testing.T, ctx context.Context,
			handler infra.Handler, m *mocks) {

			req := infra.NewRequest(ctx, &path_mgmt.HPSegReq{}, nil, nil, 0)
			res := handler.Handle(req)
			assert.Equal(t, infra.MetricsErrInternal, res)
		},
		"no messenger": func(t *testing.T, ctx context.Context,
			handler infra.Handler, m *mocks) {

			req := infra.NewRequest(context.Background(),
				&path_mgmt.HPSegReg{}, nil, nil, 0)
			res := handler.Handle(req)
			assert.Equal(t, infra.MetricsErrInternal, res)
		},
		"invalid peer address type": func(t *testing.T, ctx context.Context,
			handler infra.Handler, m *mocks) {

			msg := &path_mgmt.HPSegReg{
				HPSegRecs: &path_mgmt.HPSegRecs{
					Recs: []*seg.Meta{seg110_133},
				},
			}
			peer := &net.IPNet{}
			req := infra.NewRequest(ctx, msg, nil, peer, 0)
			ack := ack.Ack{
				Err:     proto.Ack_ErrCode_reject,
				ErrDesc: messenger.AckRejectFailedToParse,
			}
			m.rw.EXPECT().SendAckReply(gomock.Any(), &matchers.AckMsg{Ack: ack})
			res := handler.Handle(req)
			assert.Equal(t, infra.MetricsErrInvalid, res)
		},
		"group validation fails": func(t *testing.T, ctx context.Context,
			handler infra.Handler, m *mocks) {

			msg := &path_mgmt.HPSegReg{
				HPSegRecs: &path_mgmt.HPSegRecs{
					GroupId: group.Id.ToMsg(),
					Recs:    []*seg.Meta{seg110_133},
				},
			}
			peer := &snet.UDPAddr{IA: addr.IA{}, Path: spath.Path{}}
			req := infra.NewRequest(ctx, msg, nil, peer, 0)
			ack := ack.Ack{
				Err:     proto.Ack_ErrCode_reject,
				ErrDesc: "dummy",
			}
			m.validator.EXPECT().Validate(msg, peer.IA).Return(errors.New("dummy"))
			m.rw.EXPECT().SendAckReply(gomock.Any(), &matchers.AckMsg{Ack: ack})
			res := handler.Handle(req)
			assert.Equal(t, infra.MetricsErrInvalid, res)
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mocks := createMocks(ctrl)
			ctx := infra.NewContextWithResponseWriter(
				context.Background(), mocks.rw)
			handler := registration.NewSegRegHandler(
				mocks.validator,
				seghandler.Handler{
					Verifier: mocks.verifier,
					Storage:  mocks.storage,
				},
			)
			test(t, ctx, handler, mocks)
		})
	}
}

type mocks struct {
	validator *mock_registration.MockValidator
	verifier  *mock_seghandler.MockVerifier
	storage   *mock_seghandler.MockStorage
	rw        *mock_infra.MockResponseWriter
}

func createMocks(ctrl *gomock.Controller) *mocks {
	return &mocks{
		validator: mock_registration.NewMockValidator(ctrl),
		verifier:  mock_seghandler.NewMockVerifier(ctrl),
		storage:   mock_seghandler.NewMockStorage(ctrl),
		rw:        mock_infra.NewMockResponseWriter(ctrl),
	}
}
