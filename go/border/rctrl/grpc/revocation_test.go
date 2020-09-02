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

package grpc_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/border/rctrl/grpc"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	mock_cp "github.com/scionproto/scion/go/pkg/proto/control_plane/mock_control_plane"
)

func TestRevocationSenderSendRevocation(t *testing.T) {
	testCases := map[string]struct {
		Server    func(*gomock.Controller) *mock_cp.MockInterfaceStateServiceServer
		Remotes   []net.Addr
		AssertErr assert.ErrorAssertionFunc
	}{
		"No remotes": {
			Server: func(mctrl *gomock.Controller) *mock_cp.MockInterfaceStateServiceServer {
				return mock_cp.NewMockInterfaceStateServiceServer(mctrl)
			},
			AssertErr: assert.NoError,
		},
		"Single remote, RPC fail": {
			Server: func(mctrl *gomock.Controller) *mock_cp.MockInterfaceStateServiceServer {
				s := mock_cp.NewMockInterfaceStateServiceServer(mctrl)
				s.EXPECT().SignedRevocation(gomock.Any(), gomock.Any()).
					Return(nil, serrors.New("error"))
				return s
			},
			Remotes:   []net.Addr{&net.IPAddr{IP: net.IP{1, 2, 3, 4}}},
			AssertErr: assert.Error,
		},
		"Single remote, OK": {
			Server: func(mctrl *gomock.Controller) *mock_cp.MockInterfaceStateServiceServer {
				s := mock_cp.NewMockInterfaceStateServiceServer(mctrl)
				s.EXPECT().SignedRevocation(gomock.Any(), gomock.Any()).
					Return(&cppb.SignedRevocationResponse{}, nil)
				return s
			},
			Remotes:   []net.Addr{&net.IPAddr{IP: net.IP{1, 2, 3, 4}}},
			AssertErr: assert.NoError,
		},
		"Multi remote, mixed": {
			Server: func(mctrl *gomock.Controller) *mock_cp.MockInterfaceStateServiceServer {
				s := mock_cp.NewMockInterfaceStateServiceServer(mctrl)
				s.EXPECT().SignedRevocation(gomock.Any(), gomock.Any()).
					Return(&cppb.SignedRevocationResponse{}, nil)
				s.EXPECT().SignedRevocation(gomock.Any(), gomock.Any()).
					Return(nil, serrors.New("error"))
				return s
			},
			Remotes: []net.Addr{
				&net.IPAddr{IP: net.IP{1, 2, 3, 4}},
				&net.IPAddr{IP: net.IP{1, 2, 3, 5}},
			},
			AssertErr: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			svc := xtest.NewGRPCService()
			cppb.RegisterInterfaceStateServiceServer(svc.Server(), tc.Server(mctrl))
			stop := svc.Start()
			defer stop()

			s := grpc.RevocationSender{
				Dialer:      svc,
				SendCounter: metrics.NewTestCounter(),
				Logger:      log.DiscardLogger{},
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := s.SendRevocation(ctx, &path_mgmt.SignedRevInfo{}, tc.Remotes)
			tc.AssertErr(t, err)
		})
	}
}
