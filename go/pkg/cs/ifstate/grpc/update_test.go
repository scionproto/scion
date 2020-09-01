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
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/cs/ifstate/grpc"
	ifstategrpc "github.com/scionproto/scion/go/pkg/cs/ifstate/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	mock_cp "github.com/scionproto/scion/go/pkg/proto/control_plane/mock_control_plane"
)

func TestStateSenderSendStateUpdate(t *testing.T) {
	testCases := map[string]struct {
		Server    func(*gomock.Controller) *mock_cp.MockInterfaceStateConsumerServiceServer
		States    []ifstate.InterfaceState
		AssertErr assert.ErrorAssertionFunc
	}{
		"RPC fail": {
			Server: func(
				mctrl *gomock.Controller) *mock_cp.MockInterfaceStateConsumerServiceServer {

				srv := mock_cp.NewMockInterfaceStateConsumerServiceServer(mctrl)
				srv.EXPECT().InterfaceStateConsume(gomock.Any(), gomock.Any()).
					Return(nil, serrors.New("internal"))
				return srv
			},
			States:    []ifstate.InterfaceState{},
			AssertErr: assert.Error,
		},
		"OK": {
			Server: func(
				mctrl *gomock.Controller) *mock_cp.MockInterfaceStateConsumerServiceServer {

				srv := mock_cp.NewMockInterfaceStateConsumerServiceServer(mctrl)
				srv.EXPECT().InterfaceStateConsume(gomock.Any(), gomock.Any()).
					Return(&cppb.InterfaceStateConsumeResponse{}, nil)
				return srv
			},
			States:    []ifstate.InterfaceState{{ID: 25}},
			AssertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			svc := xtest.NewGRPCService()
			cppb.RegisterInterfaceStateConsumerServiceServer(svc.Server(), tc.Server(mctrl))
			stop := svc.Start()
			defer stop()

			s := ifstategrpc.StateSender{Dialer: svc}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := s.SendStateUpdate(ctx, tc.States, &net.UDPAddr{})
			tc.AssertErr(t, err)
		})
	}
}

func TestToIfStateMessage(t *testing.T) {
	sRev, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{}, infra.NullSigner)
	require.NoError(t, err)
	rawRev, err := sRev.Pack()
	require.NoError(t, err)

	testCases := map[string]struct {
		Input     []ifstate.InterfaceState
		Expected  *cppb.InterfaceStateConsumeRequest
		AssertErr assert.ErrorAssertionFunc
	}{
		"nil": {
			Input:     nil,
			Expected:  &cppb.InterfaceStateConsumeRequest{States: []*cppb.InterfaceState{}},
			AssertErr: assert.NoError,
		},
		"empty": {
			Input:     []ifstate.InterfaceState{},
			Expected:  &cppb.InterfaceStateConsumeRequest{States: []*cppb.InterfaceState{}},
			AssertErr: assert.NoError,
		},
		"state no rev": {
			Input:     []ifstate.InterfaceState{{ID: 25}},
			Expected:  &cppb.InterfaceStateConsumeRequest{States: []*cppb.InterfaceState{{Id: 25}}},
			AssertErr: assert.NoError,
		},
		"state mixed": {
			Input: []ifstate.InterfaceState{{ID: 25}, {ID: 404, Revocation: sRev}},
			Expected: &cppb.InterfaceStateConsumeRequest{States: []*cppb.InterfaceState{
				{Id: 25}, {Id: 404, SignedRev: rawRev},
			}},
			AssertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, err := grpc.ToIfStateMessage(tc.Input)
			tc.AssertErr(t, err)
			assert.Equal(t, tc.Expected, c)
		})
	}
}
