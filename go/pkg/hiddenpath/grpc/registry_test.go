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

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/peer"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	hpgrpc "github.com/scionproto/scion/go/pkg/hiddenpath/grpc"
	"github.com/scionproto/scion/go/pkg/hiddenpath/mock_hiddenpath"
	"github.com/scionproto/scion/go/pkg/proto/control_plane"
	hspb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
)

func TestRegistrationServerHiddenSegmentRegistration(t *testing.T) {
	testCases := map[string]struct {
		ctx       context.Context
		registry  func(*gomock.Controller) hiddenpath.Registry
		input     func(ctrl *gomock.Controller) *hspb.HiddenSegmentRegistrationRequest
		want      *hspb.HiddenSegmentRegistrationResponse
		assertErr assert.ErrorAssertionFunc
	}{
		"no peer in context": {
			ctx: context.Background(),
			registry: func(ctrl *gomock.Controller) hiddenpath.Registry {
				return mock_hiddenpath.NewMockRegistry(ctrl)
			},
			input: func(ctrl *gomock.Controller) *hspb.HiddenSegmentRegistrationRequest {
				return &hspb.HiddenSegmentRegistrationRequest{}
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"invalid segment": {
			ctx: peer.NewContext(context.Background(), &peer.Peer{Addr: &net.UDPAddr{}}),
			registry: func(ctrl *gomock.Controller) hiddenpath.Registry {
				return mock_hiddenpath.NewMockRegistry(ctrl)
			},
			input: func(ctrl *gomock.Controller) *hspb.HiddenSegmentRegistrationRequest {
				return &hspb.HiddenSegmentRegistrationRequest{
					Segments: map[int32]*hspb.Segments{
						1: {Segments: []*control_plane.PathSegment{
							{SegmentInfo: []byte("garbage")},
						}},
					},
				}
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"registry error": {
			ctx: peer.NewContext(context.Background(), &peer.Peer{Addr: &net.UDPAddr{}}),
			registry: func(ctrl *gomock.Controller) hiddenpath.Registry {
				registry := mock_hiddenpath.NewMockRegistry(ctrl)
				registry.EXPECT().Register(gomock.Any(), gomock.Any()).
					Return(serrors.New("test err"))
				return registry
			},
			input: func(ctrl *gomock.Controller) *hspb.HiddenSegmentRegistrationRequest {
				g := graph.NewDefaultGraph(ctrl)
				s := g.Beacon([]common.IFIDType{graph.If_110_X_120_A})

				return &hspb.HiddenSegmentRegistrationRequest{
					Segments: map[int32]*hspb.Segments{
						1: {Segments: []*control_plane.PathSegment{
							seg.PathSegmentToPB(s),
						}},
					},
				}
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"valid": {
			ctx: peer.NewContext(context.Background(), &peer.Peer{Addr: &net.UDPAddr{}}),
			registry: func(ctrl *gomock.Controller) hiddenpath.Registry {
				registry := mock_hiddenpath.NewMockRegistry(ctrl)
				registry.EXPECT().Register(gomock.Any(), gomock.Any())
				return registry
			},
			input: func(ctrl *gomock.Controller) *hspb.HiddenSegmentRegistrationRequest {
				g := graph.NewDefaultGraph(ctrl)
				s := g.Beacon([]common.IFIDType{graph.If_110_X_120_A})

				return &hspb.HiddenSegmentRegistrationRequest{
					Segments: map[int32]*hspb.Segments{
						1: {Segments: []*control_plane.PathSegment{
							seg.PathSegmentToPB(s),
						}},
					},
				}
			},
			want:      &hspb.HiddenSegmentRegistrationResponse{},
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			s := hpgrpc.RegistrationServer{
				Registry: tc.registry(ctrl),
			}
			got, err := s.HiddenSegmentRegistration(tc.ctx, tc.input(ctrl))
			assert.Equal(t, tc.want, got)
			tc.assertErr(t, err)
		})
	}
}
