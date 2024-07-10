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
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/peer"

	"github.com/scionproto/scion/gateway/control/grpc"
	"github.com/scionproto/scion/gateway/control/grpc/mock_grpc"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
	gpb "github.com/scionproto/scion/pkg/proto/gateway"
	"github.com/scionproto/scion/pkg/snet"
)

func TestIPPrefixServerPrefixes(t *testing.T) {
	local := addr.MustParseIA("1-ff00:0:110")
	remote := addr.MustParseIA("1-ff00:0:111")

	testCases := map[string]struct {
		Advertiser   func(t *testing.T, ctrl *gomock.Controller) grpc.Advertiser
		Request      func() (context.Context, *gpb.PrefixesRequest)
		ErrAssertion assert.ErrorAssertionFunc
		Expected     []*net.IPNet
	}{
		"valid": {
			Advertiser: func(t *testing.T, ctrl *gomock.Controller) grpc.Advertiser {
				a := mock_grpc.NewMockAdvertiser(ctrl)
				a.EXPECT().AdvertiseList(local, remote).Return(
					xtest.MustParseIPPrefixes(t, "127.0.0.0/24", "127.0.1.0/24", "::/64"), nil)
				return a
			},
			Request: func() (context.Context, *gpb.PrefixesRequest) {
				ctx := peer.NewContext(context.Background(),
					&peer.Peer{Addr: &snet.UDPAddr{IA: remote}},
				)
				return ctx, &gpb.PrefixesRequest{}
			},
			Expected:     networksList(t, "127.0.0.0/24,127.0.1.0/24,::/64"),
			ErrAssertion: assert.NoError,
		},
		"unknown": {
			Advertiser: func(t *testing.T, ctrl *gomock.Controller) grpc.Advertiser {
				a := mock_grpc.NewMockAdvertiser(ctrl)
				a.EXPECT().AdvertiseList(local, remote).Return(nil, nil)
				return a
			},
			Request: func() (context.Context, *gpb.PrefixesRequest) {
				ctx := peer.NewContext(context.Background(),
					&peer.Peer{Addr: &snet.UDPAddr{IA: remote}},
				)
				return ctx, &gpb.PrefixesRequest{}
			},
			ErrAssertion: assert.NoError,
		},
		"no peer": {
			Advertiser: func(t *testing.T, ctrl *gomock.Controller) grpc.Advertiser {
				return mock_grpc.NewMockAdvertiser(ctrl)
			},
			Request: func() (context.Context, *gpb.PrefixesRequest) {
				return context.Background(), &gpb.PrefixesRequest{}
			},
			ErrAssertion: assert.Error,
		},
		"not SCION address": {
			Advertiser: func(t *testing.T, ctrl *gomock.Controller) grpc.Advertiser {
				return mock_grpc.NewMockAdvertiser(ctrl)
			},
			Request: func() (context.Context, *gpb.PrefixesRequest) {
				ctx := peer.NewContext(context.Background(),
					&peer.Peer{Addr: &net.UDPAddr{}},
				)
				return ctx, &gpb.PrefixesRequest{}
			},
			ErrAssertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			s := grpc.IPPrefixServer{
				LocalIA:    local,
				Advertiser: tc.Advertiser(t, ctrl),
			}
			rep, err := s.Prefixes(tc.Request())
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}
			var got []*net.IPNet
			for _, pb := range rep.Prefixes {
				prefix := &net.IPNet{
					IP:   net.IP(pb.Prefix),
					Mask: net.CIDRMask(int(pb.Mask), len(pb.Prefix)*8),
				}
				got = append(got, prefix)
			}
			assert.ElementsMatch(t, tc.Expected, got)
		})
	}
}

func networksList(t *testing.T, networks string) []*net.IPNet {
	var prefixes []*net.IPNet
	for _, network := range strings.Split(networks, ",") {
		_, n, err := net.ParseCIDR(network)
		require.NoError(t, err)
		if v4 := n.IP.To4(); v4 != nil {
			n.IP = v4
		}
		prefixes = append(prefixes, n)
	}
	return prefixes
}
