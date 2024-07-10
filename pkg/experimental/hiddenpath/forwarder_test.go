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

package hiddenpath_test

import (
	"context"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath/mock_hiddenpath"
	seg "github.com/scionproto/scion/pkg/segment"
)

func TestForwardServerSegments(t *testing.T) {
	local := addr.MustParseIA("1-ff00:0:110")
	testCases := map[string]struct {
		request   hiddenpath.SegmentRequest
		groups    func() map[hiddenpath.GroupID]*hiddenpath.Group
		local     addr.IA
		rpc       func(*gomock.Controller) hiddenpath.RPC
		verifier  func(*gomock.Controller) hiddenpath.Verifier
		lookuper  func(*gomock.Controller) hiddenpath.Lookuper
		want      []*seg.Meta
		assertErr assert.ErrorAssertionFunc
	}{
		"valid": {
			request: hiddenpath.SegmentRequest{
				GroupIDs: []hiddenpath.GroupID{
					{OwnerAS: addr.MustParseAS("ff00:0:110")},
					{OwnerAS: addr.MustParseAS("ff00:0:111")},
					{OwnerAS: addr.MustParseAS("ff00:0:112")},
				},
				DstIA: addr.MustParseIA("2-ff00:0:22"),
			},
			rpc: func(c *gomock.Controller) hiddenpath.RPC {
				ret := mock_hiddenpath.NewMockRPC(c)
				ret.EXPECT().HiddenSegments(gomock.Any(), hiddenpath.SegmentRequest{
					GroupIDs: []hiddenpath.GroupID{
						{OwnerAS: addr.MustParseAS("ff00:0:111")},
						{OwnerAS: addr.MustParseAS("ff00:0:112")},
					},
					DstIA: addr.MustParseIA("2-ff00:0:22"),
				},
					gomock.Any()).Return([]*seg.Meta{{Type: seg.TypeDown}}, nil).
					Times(1)
				return ret
			},
			lookuper: func(c *gomock.Controller) hiddenpath.Lookuper {
				ret := mock_hiddenpath.NewMockLookuper(c)
				ret.EXPECT().Segments(gomock.Any(), hiddenpath.SegmentRequest{
					GroupIDs: []hiddenpath.GroupID{
						{OwnerAS: addr.MustParseAS("ff00:0:110")},
					},
					DstIA: addr.MustParseIA("2-ff00:0:22"),
					Peer:  addr.MustParseIA("1-ff00:0:110"),
				}).
					Return([]*seg.Meta{{Type: seg.TypeDown}}, nil).
					Times(1)
				return ret
			},
			verifier: func(c *gomock.Controller) hiddenpath.Verifier {
				ret := mock_hiddenpath.NewMockVerifier(c)
				ret.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).
					Times(1)
				return ret
			},
			groups: func() map[hiddenpath.GroupID]*hiddenpath.Group {
				return map[hiddenpath.GroupID]*hiddenpath.Group{
					{OwnerAS: addr.MustParseAS("ff00:0:110")}: {
						ID:         hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:110")},
						Registries: map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:110"): {}},
					},
					{OwnerAS: addr.MustParseAS("ff00:0:111")}: {
						ID:         hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:111")},
						Registries: map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:111"): {}},
					},
					{OwnerAS: addr.MustParseAS("ff00:0:112")}: {
						ID:         hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:112")},
						Registries: map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:111"): {}},
					},
				}
			},
			want:      []*seg.Meta{{Type: seg.TypeDown}, {Type: seg.TypeDown}},
			assertErr: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			resolver := mock_hiddenpath.NewMockAddressResolver(ctrl)
			resolver.EXPECT().Resolve(gomock.Any(), gomock.Any()).Return(&net.UDPAddr{}, nil).
				AnyTimes()

			server := hiddenpath.ForwardServer{
				Groups:    tc.groups(),
				RPC:       tc.rpc(ctrl),
				LocalAuth: tc.lookuper(ctrl),
				LocalIA:   local,
				Verifier:  tc.verifier(ctrl),
				Resolver:  resolver,
			}
			got, err := server.Segments(context.Background(), tc.request)
			tc.assertErr(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

}
