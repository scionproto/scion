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
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/peer"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	"github.com/scionproto/scion/go/pkg/hiddenpath/grpc"
	"github.com/scionproto/scion/go/pkg/hiddenpath/mock_hiddenpath"
	"github.com/scionproto/scion/go/pkg/proto/control_plane"
	hspb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
)

func TestSegmentServerHiddenSegments(t *testing.T) {

	segsMeta, wantPB := createSegs()

	testCases := map[string]struct {
		createCtx     func(t *testing.T) context.Context
		lookuper      func(ctrl *gomock.Controller) hiddenpath.Lookuper
		request       *hspb.HiddenSegmentsRequest
		want          *hspb.HiddenSegmentsResponse
		authoritative bool
		assertErr     assert.ErrorAssertionFunc
	}{
		"authoritative context without peer": {
			createCtx: func(t *testing.T) context.Context { return context.Background() },
			lookuper: func(ctrl *gomock.Controller) hiddenpath.Lookuper {
				return mock_hiddenpath.NewMockLookuper(ctrl)
			},
			request: &hspb.HiddenSegmentsRequest{
				GroupIds: groupIDsToInts(mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5")),
				DstIsdAs: mustIA("1-ff00:0:110"),
			},
			authoritative: true,
			want:          nil,
			assertErr:     assert.Error,
		},
		"authoritative context with invalid peer": {
			createCtx: func(t *testing.T) context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{Addr: &net.UDPAddr{
					IP: net.ParseIP("127.0.0.1"),
				}})
			},
			lookuper: func(ctrl *gomock.Controller) hiddenpath.Lookuper {
				return mock_hiddenpath.NewMockLookuper(ctrl)
			},
			request: &hspb.HiddenSegmentsRequest{
				GroupIds: groupIDsToInts(mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5")),
				DstIsdAs: mustIA("1-ff00:0:110"),
			},
			authoritative: true,
			want:          nil,
			assertErr:     assert.Error,
		},
		"autoritative lookuper error": {
			createCtx: func(t *testing.T) context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{Addr: &snet.UDPAddr{
					IA: xtest.MustParseIA("1-ff00:0:14"),
				}})
			},
			lookuper: func(ctrl *gomock.Controller) hiddenpath.Lookuper {
				lookuper := mock_hiddenpath.NewMockLookuper(ctrl)
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
			authoritative: true,
			want:          nil,
			assertErr:     assert.Error,
		},
		"autoritative valid": {
			createCtx: func(t *testing.T) context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{Addr: &snet.UDPAddr{
					IA: xtest.MustParseIA("1-ff00:0:14"),
				}})
			},
			lookuper: func(ctrl *gomock.Controller) hiddenpath.Lookuper {
				lookuper := mock_hiddenpath.NewMockLookuper(ctrl)
				lookuper.EXPECT().Segments(gomock.Any(), hiddenpath.SegmentRequest{
					GroupIDs: mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5"),
					DstIA:    xtest.MustParseIA("1-ff00:0:110"),
					Peer:     xtest.MustParseIA("1-ff00:0:14"),
				}).Return(segsMeta, nil)
				return lookuper
			},
			request: &hspb.HiddenSegmentsRequest{
				GroupIds: groupIDsToInts(mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5")),
				DstIsdAs: mustIA("1-ff00:0:110"),
			},
			authoritative: true,
			want:          wantPB,
			assertErr:     assert.NoError,
		},
		"forwarder valid": {
			createCtx: func(t *testing.T) context.Context { return context.Background() },
			lookuper: func(ctrl *gomock.Controller) hiddenpath.Lookuper {
				ret := mock_hiddenpath.NewMockLookuper(ctrl)
				ret.EXPECT().Segments(gomock.Any(), hiddenpath.SegmentRequest{
					GroupIDs: mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5"),
					DstIA:    xtest.MustParseIA("1-ff00:0:110"),
				}).Return(segsMeta, nil).Times(1)
				return ret
			},
			request: &hspb.HiddenSegmentsRequest{
				GroupIds: groupIDsToInts(mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5")),
				DstIsdAs: mustIA("1-ff00:0:110"),
			},
			want:      wantPB,
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
				Lookup:        tc.lookuper(ctrl),
				Authoritative: tc.authoritative,
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

func createSegs() ([]*seg.Meta, *hspb.HiddenSegmentsResponse) {
	asEntry := seg.ASEntry{
		Local: xtest.MustParseIA("1-ff00:0:110"),
		HopEntry: seg.HopEntry{
			HopField: seg.HopField{MAC: bytes.Repeat([]byte{0x11}, 6)},
		},
	}
	ps, _ := seg.CreateSegment(time.Now(), 1337)
	ps.AddASEntry(context.Background(), asEntry, graph.NewSigner())

	ret1 := []*seg.Meta{{Type: seg.TypeDown, Segment: ps}}
	ret2 := &hspb.HiddenSegmentsResponse{
		Segments: map[int32]*hspb.Segments{
			2: {Segments: []*control_plane.PathSegment{
				seg.PathSegmentToPB(ps),
			}},
		},
	}
	return ret1, ret2
}
