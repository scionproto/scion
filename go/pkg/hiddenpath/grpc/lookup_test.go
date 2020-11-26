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

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	"github.com/scionproto/scion/go/pkg/hiddenpath/grpc"
	"github.com/scionproto/scion/go/pkg/hiddenpath/grpc/mock_grpc"
	hspb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
)

func TestSegmentServerHiddenSegments(t *testing.T) {
	testCases := map[string]struct {
		createCtx func(t *testing.T) context.Context
		lookuper  func(ctrl *gomock.Controller) grpc.Lookuper
		request   *hspb.HiddenSegmentsRequest
		want      *hspb.HiddenSegmentsResponse
		assertErr assert.ErrorAssertionFunc
	}{
		"context without peer": {
			createCtx: func(t *testing.T) context.Context { return context.Background() },
			lookuper: func(ctrl *gomock.Controller) grpc.Lookuper {
				return mock_grpc.NewMockLookuper(ctrl)
			},
			request: &hspb.HiddenSegmentsRequest{
				GroupIds: groupIDsToInts(mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5")),
				DstIsdAs: mustIA("1-ff00:0:110"),
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"context with invalid peer": {
			createCtx: func(t *testing.T) context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{Addr: &net.UDPAddr{
					IP: net.ParseIP("127.0.0.1"),
				}})
			},
			lookuper: func(ctrl *gomock.Controller) grpc.Lookuper {
				return mock_grpc.NewMockLookuper(ctrl)
			},
			request: &hspb.HiddenSegmentsRequest{
				GroupIds: groupIDsToInts(mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5")),
				DstIsdAs: mustIA("1-ff00:0:110"),
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"lookuper error": {
			createCtx: func(t *testing.T) context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{Addr: &snet.UDPAddr{
					IA: xtest.MustParseIA("1-ff00:0:14"),
				}})
			},
			lookuper: func(ctrl *gomock.Controller) grpc.Lookuper {
				lookuper := mock_grpc.NewMockLookuper(ctrl)
				lookuper.EXPECT().Segments(gomock.Any(), hiddenpath.SegmentRequest{
					GroupIDs: mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5"),
					DstIA:    xtest.MustParseIA("1-ff00:0:110"),
					Peer:     xtest.MustParseIA("1-ff00:0:14"),
				}).Return(nil, serrors.New("test error"))
				return lookuper
			},
			request: &hspb.HiddenSegmentsRequest{
				GroupIds: groupIDsToInts(mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5")),
				DstIsdAs: mustIA("1-ff00:0:110"),
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"valid": {
			createCtx: func(t *testing.T) context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{Addr: &snet.UDPAddr{
					IA: xtest.MustParseIA("1-ff00:0:14"),
				}})
			},
			lookuper: func(ctrl *gomock.Controller) grpc.Lookuper {
				lookuper := mock_grpc.NewMockLookuper(ctrl)
				lookuper.EXPECT().Segments(gomock.Any(), hiddenpath.SegmentRequest{
					GroupIDs: mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5"),
					DstIA:    xtest.MustParseIA("1-ff00:0:110"),
					Peer:     xtest.MustParseIA("1-ff00:0:14"),
				}).Return(nil, nil)
				// XXX(lukedirtwalker): would be nice to actually return some
				// values.
				return lookuper
			},
			request: &hspb.HiddenSegmentsRequest{
				GroupIds: groupIDsToInts(mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5")),
				DstIsdAs: mustIA("1-ff00:0:110"),
			},
			want: &hspb.HiddenSegmentsResponse{
				Segments: make(map[int32]*hspb.Segments),
			},
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			server := &grpc.SegmentServer{
				Lookup: tc.lookuper(ctrl),
			}
			got, err := server.HiddenSegments(tc.createCtx(t), tc.request)
			tc.assertErr(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func mustIA(s string) uint64 {
	return uint64(xtest.MustParseIA(s).IAInt())
}

func mustParseGroupIDs(t *testing.T, ids ...string) []hiddenpath.GroupID {
	t.Helper()

	result := make([]hiddenpath.GroupID, 0, len(ids))
	for _, id := range ids {
		result = append(result, mustParseGroupID(t, id))
	}
	return result
}

func mustParseGroupID(t *testing.T, s string) hiddenpath.GroupID {
	t.Helper()

	id, err := hiddenpath.ParseGroupID(s)
	require.NoError(t, err)
	return id
}

func groupIDsToInts(ids []hiddenpath.GroupID) []uint64 {
	result := make([]uint64, 0, len(ids))
	for _, id := range ids {
		result = append(result, id.ToUint64())
	}
	return result
}
