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
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher/mock_segfetcher"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	hpgrpc "github.com/scionproto/scion/go/pkg/hiddenpath/grpc"
	"github.com/scionproto/scion/go/pkg/hiddenpath/grpc/mock_grpc"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	hspb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
	"github.com/scionproto/scion/go/pkg/proto/hidden_segment/mock_hidden_segment"
)

func TestRequesterSegments(t *testing.T) {
	testSeg := createSeg()
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
			hpGroups    hiddenpath.Groups
			input       segfetcher.Request
			regular     func(*gomock.Controller) segfetcher.RPC
			want        int
			assertError assert.ErrorAssertionFunc
		}{
			"dst in writers": {
				hpGroups: defaultGroups,
				regular: func(c *gomock.Controller) segfetcher.RPC {
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
				regular: func(c *gomock.Controller) segfetcher.RPC {
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
				regular: func(c *gomock.Controller) segfetcher.RPC {
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

				server := mock_hidden_segment.NewMockHiddenSegmentLookupServiceServer(ctrl)
				server.EXPECT().HiddenSegments(gomock.Any(), gomock.Any()).
					Return(&hspb.HiddenSegmentsResponse{
						Segments: hpgrpc.ToHSPB([]*seg.Meta{&testSeg}),
					}, nil).AnyTimes()
				svc := xtest.NewGRPCService()
				hspb.RegisterHiddenSegmentLookupServiceServer(svc.Server(), server)
				svc.Start(t)

				requester := &hpgrpc.Requester{
					Dialer:        svc,
					RegularLookup: tc.regular(ctrl),
					HPGroups:      tc.hpGroups,
				}

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				got, err := requester.Segments(ctx, tc.input, &net.UDPAddr{})
				tc.assertError(t, err)
				assert.Equal(t, tc.want, len(got))
			})
		}
	})
}

func TestAuthoritativeRequesterHiddenSegments(t *testing.T) {
	testSeg := createSeg()
	testCases := map[string]struct {
		input       hiddenpath.SegmentRequest
		signer      func(*gomock.Controller) hpgrpc.Signer
		server      func(*gomock.Controller) hspb.AuthoritativeHiddenSegmentLookupServiceServer
		want        int
		assertError assert.ErrorAssertionFunc
	}{
		"valid": {
			input: hiddenpath.SegmentRequest{
				GroupIDs: []hiddenpath.GroupID{mustParseGroupID(t, "ff00:0:42-404")},
				DstIA:    xtest.MustParseIA("1-ff00:0:3"),
			},
			signer: func(ctrl *gomock.Controller) hpgrpc.Signer {
				s := mock_grpc.NewMockSigner(ctrl)
				s.EXPECT().Sign(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&cryptopb.SignedMessage{}, nil)
				return s
			},
			server: func(
				ctrl *gomock.Controller) hspb.AuthoritativeHiddenSegmentLookupServiceServer {

				s := mock_hidden_segment.NewMockAuthoritativeHiddenSegmentLookupServiceServer(ctrl)
				s.EXPECT().AuthoritativeHiddenSegments(gomock.Any(), gomock.Any()).
					Return(&hspb.AuthoritativeHiddenSegmentsResponse{
						Segments: hpgrpc.ToHSPB([]*seg.Meta{&testSeg}),
					}, nil)
				return s
			},
			want:        1,
			assertError: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			svc := xtest.NewGRPCService()
			hspb.RegisterAuthoritativeHiddenSegmentLookupServiceServer(svc.Server(),
				tc.server(ctrl))
			svc.Start(t)

			requester := &hpgrpc.AuthoritativeRequester{
				Dialer: svc,
				Signer: tc.signer(ctrl),
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			got, err := requester.HiddenSegments(ctx, tc.input, &net.UDPAddr{})
			tc.assertError(t, err)
			assert.Equal(t, tc.want, len(got))
		})
	}
}
