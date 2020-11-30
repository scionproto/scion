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

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	hpgrpc "github.com/scionproto/scion/go/pkg/hiddenpath/grpc"
	"github.com/scionproto/scion/go/pkg/proto/discovery"
	dspb "github.com/scionproto/scion/go/pkg/proto/discovery"
	"github.com/scionproto/scion/go/pkg/proto/discovery/mock_discovery"
)

func TestDiscovererDiscover(t *testing.T) {
	testCases := map[string]struct {
		server    func(*gomock.Controller) discovery.DiscoveryServiceServer
		want      hiddenpath.Servers
		assertErr assert.ErrorAssertionFunc
	}{
		"valid both entries": {
			server: func(ctrl *gomock.Controller) dspb.DiscoveryServiceServer {
				s := mock_discovery.NewMockDiscoveryServiceServer(ctrl)
				s.EXPECT().HiddenSegmentServices(gomock.Any(), gomock.Any()).Return(
					&dspb.HiddenSegmentServicesResponse{
						Lookup: []*dspb.HiddenSegmentLookupServer{
							{Address: "10.0.0.1:404"},
							{Address: "10.0.0.2:405"},
						},
						Registration: []*dspb.HiddenSegmentRegistrationServer{
							{Address: "10.0.0.3:404"},
							{Address: "10.0.0.4:405"},
						},
					}, nil,
				)
				return s
			},
			want: hiddenpath.Servers{
				Lookup: []*net.UDPAddr{
					xtest.MustParseUDPAddr(t, "10.0.0.1:404"),
					xtest.MustParseUDPAddr(t, "10.0.0.2:405"),
				},
				Registration: []*net.UDPAddr{
					xtest.MustParseUDPAddr(t, "10.0.0.3:404"),
					xtest.MustParseUDPAddr(t, "10.0.0.4:405"),
				},
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

			svc := xtest.NewGRPCService()
			dspb.RegisterDiscoveryServiceServer(svc.Server(), tc.server(ctrl))
			svc.Start(t)

			d := hpgrpc.Discoverer{Dialer: svc}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := d.Discover(ctx, &net.UDPAddr{})
			tc.assertErr(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
