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
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher/mock_segfetcher"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	hpgrpc "github.com/scionproto/scion/go/pkg/hiddenpath/grpc"
	"github.com/scionproto/scion/go/pkg/proto/control_plane"
	hppb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
)

func TestRequesterSegments(t *testing.T) {
	lis, err := net.Listen("tcp4", "127.0.0.1:0")
	assert.NoError(t, err)
	defer lis.Close()
	s := grpc.NewServer()
	hppb.RegisterHiddenSegmentLookupServiceServer(s, &hiddenLookupServer{})
	go func() { s.Serve(lis) }()
	defer s.Stop()

	hpID := hiddenpath.GroupID{
		OwnerAS: xtest.MustParseAS("ff00:0:2"),
		Suffix:  15,
	}
	defaultGroups := hiddenpath.Groups{
		hpID: {
			ID: hpID,
			Writers: map[addr.IA]struct{}{
				xtest.MustParseIA("1-ff00:0:3"): {},
			},
		},
	}

	t.Run("cases", func(t *testing.T) {
		testCases := map[string]struct {
			hpGroups             hiddenpath.Groups
			input                segfetcher.Request
			prepareRegularLookup func(*gomock.Controller) segfetcher.RPC
			want                 int
			assertError          assert.ErrorAssertionFunc
		}{
			"dst in writers": {
				hpGroups: defaultGroups,
				prepareRegularLookup: func(c *gomock.Controller) segfetcher.RPC {
					ret := mock_segfetcher.NewMockRPC(c)
					ret.EXPECT().Segments(gomock.Any(), gomock.Any(), gomock.Any()).
						Return(nil, nil).Times(1)
					return ret
				},
				input: segfetcher.Request{
					Dst: xtest.MustParseIA("1-ff00:0:3"),
				},
				want:        1,
				assertError: assert.NoError,
			},
			"dst not in writers": {
				hpGroups: defaultGroups,
				prepareRegularLookup: func(c *gomock.Controller) segfetcher.RPC {
					ret := mock_segfetcher.NewMockRPC(c)
					ret.EXPECT().Segments(gomock.Any(), gomock.Any(), gomock.Any()).
						Return(nil, nil).Times(1)
					return ret
				},
				input: segfetcher.Request{
					Dst: xtest.MustParseIA("1-ff00:0:7"),
				},
				want:        0,
				assertError: assert.NoError,
			},
			"invalid": {
				hpGroups: defaultGroups,
				prepareRegularLookup: func(c *gomock.Controller) segfetcher.RPC {
					ret := mock_segfetcher.NewMockRPC(c)
					ret.EXPECT().Segments(gomock.Any(), gomock.Any(), gomock.Any()).
						Return(nil, fmt.Errorf("dummy-error")).Times(1)
					return ret
				},
				input: segfetcher.Request{
					Dst: xtest.MustParseIA("1-ff00:0:3"),
				},
				want:        0,
				assertError: assert.Error,
			},
		}

		for name, tc := range testCases {
			name, tc := name, tc
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()

				requester := &hpgrpc.Requester{
					Dialer:        &libgrpc.TCPDialer{},
					RegularLookup: tc.prepareRegularLookup(ctrl),
					HPGroups:      tc.hpGroups,
				}

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				got, err := requester.Segments(ctx, tc.input, lis.Addr())
				tc.assertError(t, err)
				assert.Equal(t, tc.want, len(got))
			})
		}
	})
}

type hiddenLookupServer struct{}

func (s hiddenLookupServer) HiddenSegments(ctx context.Context,
	req *hppb.HiddenSegmentsRequest) (*hppb.HiddenSegmentsResponse, error) {

	createSeg := func() *control_plane.PathSegment {
		asEntry := seg.ASEntry{
			Local: xtest.MustParseIA("1-ff00:0:110"),
			HopEntry: seg.HopEntry{
				HopField: seg.HopField{MAC: bytes.Repeat([]byte{0x11}, 6)},
			},
		}
		ps, _ := seg.CreateSegment(time.Now(), 1337)
		ps.AddASEntry(context.Background(), asEntry, graph.NewSigner())
		return seg.PathSegmentToPB(ps)
	}

	return &hppb.HiddenSegmentsResponse{
		Segments: map[int32]*hppb.Segments{
			2: {Segments: []*control_plane.PathSegment{
				createSeg(),
			}},
		},
	}, nil
}
