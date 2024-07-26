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
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	hpgrpc "github.com/scionproto/scion/pkg/experimental/hiddenpath/grpc"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath/mock_hiddenpath"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	"github.com/scionproto/scion/pkg/proto/control_plane"
	hspb "github.com/scionproto/scion/pkg/proto/hidden_segment"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet"
	infra "github.com/scionproto/scion/private/segment/verifier"
	mock_infra "github.com/scionproto/scion/private/segment/verifier/mock_verifier"
)

func TestRegistrationServerHiddenSegmentRegistration(t *testing.T) {
	marshalBody := func(t *testing.T, body *hspb.HiddenSegmentRegistrationRequestBody) []byte {
		r, err := proto.Marshal(body)
		require.NoError(t, err)
		return r
	}

	testCases := map[string]struct {
		ctx       context.Context
		registry  func(*gomock.Controller) hiddenpath.Registry
		verifier  func(ctrl *gomock.Controller) infra.Verifier
		want      *hspb.HiddenSegmentRegistrationResponse
		assertErr assert.ErrorAssertionFunc
	}{
		"no peer in context": {
			ctx: context.Background(),
			registry: func(ctrl *gomock.Controller) hiddenpath.Registry {
				return mock_hiddenpath.NewMockRegistry(ctrl)
			},
			verifier: func(ctrl *gomock.Controller) infra.Verifier {
				return mock_infra.NewMockVerifier(ctrl)
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"invalid peer": {
			ctx: peer.NewContext(context.Background(), &peer.Peer{Addr: &net.UDPAddr{}}),
			registry: func(ctrl *gomock.Controller) hiddenpath.Registry {
				return mock_hiddenpath.NewMockRegistry(ctrl)
			},
			verifier: func(ctrl *gomock.Controller) infra.Verifier {
				return mock_infra.NewMockVerifier(ctrl)
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"invalid segment": {
			ctx: peer.NewContext(context.Background(), &peer.Peer{Addr: &snet.UDPAddr{
				IA: addr.MustParseIA("1-ff00:0:110"),
			}}),
			registry: func(ctrl *gomock.Controller) hiddenpath.Registry {
				return mock_hiddenpath.NewMockRegistry(ctrl)
			},
			verifier: func(ctrl *gomock.Controller) infra.Verifier {
				body := marshalBody(t, &hspb.HiddenSegmentRegistrationRequestBody{
					Segments: map[int32]*hspb.Segments{
						1: {Segments: []*control_plane.PathSegment{
							{SegmentInfo: []byte("garbage")},
						}},
					},
				})
				v := mock_infra.NewMockVerifier(ctrl)
				v.EXPECT().WithServer(gomock.Any()).Return(v)
				v.EXPECT().WithIA(addr.MustParseIA("1-ff00:0:110")).Return(v)
				v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(&signed.Message{
					Body: body,
				}, nil)
				return v
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"signature verification error": {
			ctx: peer.NewContext(context.Background(), &peer.Peer{Addr: &snet.UDPAddr{
				IA: addr.MustParseIA("1-ff00:0:110"),
			}}),
			registry: func(ctrl *gomock.Controller) hiddenpath.Registry {
				return mock_hiddenpath.NewMockRegistry(ctrl)
			},
			verifier: func(ctrl *gomock.Controller) infra.Verifier {
				g := graph.NewDefaultGraph(ctrl)
				s := g.Beacon([]uint16{graph.If_110_X_120_A})

				body := marshalBody(t, &hspb.HiddenSegmentRegistrationRequestBody{
					Segments: map[int32]*hspb.Segments{
						1: {Segments: []*control_plane.PathSegment{
							seg.PathSegmentToPB(s),
						}},
					},
				})
				v := mock_infra.NewMockVerifier(ctrl)
				v.EXPECT().WithServer(gomock.Any()).Return(v)
				v.EXPECT().WithIA(addr.MustParseIA("1-ff00:0:110")).Return(v)
				v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(&signed.Message{
					Body: body,
				}, serrors.New("verification failed"))
				return v
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"invalid body": {
			ctx: peer.NewContext(context.Background(), &peer.Peer{Addr: &snet.UDPAddr{
				IA: addr.MustParseIA("1-ff00:0:110"),
			}}),
			registry: func(ctrl *gomock.Controller) hiddenpath.Registry {
				return mock_hiddenpath.NewMockRegistry(ctrl)
			},
			verifier: func(ctrl *gomock.Controller) infra.Verifier {
				body := []byte("garbage")
				v := mock_infra.NewMockVerifier(ctrl)
				v.EXPECT().WithServer(gomock.Any()).Return(v)
				v.EXPECT().WithIA(addr.MustParseIA("1-ff00:0:110")).Return(v)
				v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(&signed.Message{
					Body: body,
				}, nil)
				return v
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"registry error": {
			ctx: peer.NewContext(context.Background(), &peer.Peer{Addr: &snet.UDPAddr{
				IA: addr.MustParseIA("1-ff00:0:110"),
			}}),
			registry: func(ctrl *gomock.Controller) hiddenpath.Registry {
				registry := mock_hiddenpath.NewMockRegistry(ctrl)
				registry.EXPECT().Register(gomock.Any(), gomock.Any()).
					Return(serrors.New("test err"))
				return registry
			},
			verifier: func(ctrl *gomock.Controller) infra.Verifier {
				g := graph.NewDefaultGraph(ctrl)
				s := g.Beacon([]uint16{graph.If_110_X_120_A})

				body := marshalBody(t, &hspb.HiddenSegmentRegistrationRequestBody{
					Segments: map[int32]*hspb.Segments{
						1: {Segments: []*control_plane.PathSegment{
							seg.PathSegmentToPB(s),
						}},
					},
				})
				v := mock_infra.NewMockVerifier(ctrl)
				v.EXPECT().WithServer(gomock.Any()).Return(v)
				v.EXPECT().WithIA(addr.MustParseIA("1-ff00:0:110")).Return(v)
				v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(&signed.Message{
					Body: body,
				}, nil)
				return v
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"valid": {
			ctx: peer.NewContext(context.Background(), &peer.Peer{Addr: &snet.UDPAddr{
				IA: addr.MustParseIA("1-ff00:0:110"),
			}}),
			registry: func(ctrl *gomock.Controller) hiddenpath.Registry {
				registry := mock_hiddenpath.NewMockRegistry(ctrl)
				registry.EXPECT().Register(gomock.Any(), gomock.Any())
				return registry
			},
			verifier: func(ctrl *gomock.Controller) infra.Verifier {
				g := graph.NewDefaultGraph(ctrl)
				s := g.Beacon([]uint16{graph.If_110_X_120_A})

				body := marshalBody(t, &hspb.HiddenSegmentRegistrationRequestBody{
					Segments: map[int32]*hspb.Segments{
						1: {Segments: []*control_plane.PathSegment{
							seg.PathSegmentToPB(s),
						}},
					},
				})
				v := mock_infra.NewMockVerifier(ctrl)
				v.EXPECT().WithServer(gomock.Any()).Return(v)
				v.EXPECT().WithIA(addr.MustParseIA("1-ff00:0:110")).Return(v)
				v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(&signed.Message{
					Body: body,
				}, nil)
				return v
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
				Verifier: tc.verifier(ctrl),
			}
			got, err := s.HiddenSegmentRegistration(tc.ctx,
				&hspb.HiddenSegmentRegistrationRequest{})
			assert.Equal(t, tc.want, got)
			tc.assertErr(t, err)
		})
	}
}
