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

package discovery_test

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/private/xtest"
	dpb "github.com/scionproto/scion/pkg/proto/discovery"
	"github.com/scionproto/scion/private/discovery"
	"github.com/scionproto/scion/private/discovery/mock_discovery"
	"github.com/scionproto/scion/private/topology"
)

func TestGateways(t *testing.T) {
	testCases := map[string]struct {
		info        func(*testing.T, *gomock.Controller) discovery.TopologyInformation
		want        *dpb.GatewaysResponse
		assertError assert.ErrorAssertionFunc
	}{
		"valid": {
			info: func(t *testing.T, ctrl *gomock.Controller) discovery.TopologyInformation {
				info := mock_discovery.NewMockTopologyInformation(ctrl)
				info.EXPECT().Gateways().Return(
					[]topology.GatewayInfo{
						{
							CtrlAddr: &topology.TopoAddr{
								SCIONAddress: xtest.MustParseUDPAddr(t, "127.0.0.82:30100"),
							},
							DataAddr:        xtest.MustParseUDPAddr(t, "127.0.0.82:30101"),
							ProbeAddr:       xtest.MustParseUDPAddr(t, "127.0.0.82:30102"),
							AllowInterfaces: []uint64{1, 3, 5},
						},
						{
							CtrlAddr: &topology.TopoAddr{
								SCIONAddress: xtest.MustParseUDPAddr(t,
									"[2001:db8:f00:b43::1%some-zone]:23425"),
							},
							DataAddr: xtest.MustParseUDPAddr(t,
								"[2001:db8:f00:b43::1%some-zone]:30101"),
							ProbeAddr: xtest.MustParseUDPAddr(t,
								"[2001:db8:f00:b43::1%some-zone]:30102"),
						},
					},
					nil,
				)
				return info
			},
			want: &dpb.GatewaysResponse{
				Gateways: []*dpb.Gateway{
					{
						ControlAddress:  "127.0.0.82:30100",
						DataAddress:     "127.0.0.82:30101",
						ProbeAddress:    "127.0.0.82:30102",
						AllowInterfaces: []uint64{1, 3, 5},
					},
					{
						ControlAddress: "[2001:db8:f00:b43::1%some-zone]:23425",
						DataAddress:    "[2001:db8:f00:b43::1%some-zone]:30101",
						ProbeAddress:   "[2001:db8:f00:b43::1%some-zone]:30102",
					},
				},
			},
			assertError: assert.NoError,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			d := discovery.Topology{
				Information: tc.info(t, ctrl),
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			got, err := d.Gateways(ctx, nil)
			tc.assertError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestHiddenSegmentServices(t *testing.T) {
	testCases := map[string]struct {
		info        func(*testing.T, *gomock.Controller) discovery.TopologyInformation
		want        *dpb.HiddenSegmentServicesResponse
		assertError assert.ErrorAssertionFunc
	}{
		"no service": {
			info: func(_ *testing.T, ctrl *gomock.Controller) discovery.TopologyInformation {
				info := mock_discovery.NewMockTopologyInformation(ctrl)
				info.EXPECT().HiddenSegmentLookupAddresses()
				info.EXPECT().HiddenSegmentRegistrationAddresses()
				return info
			},
			want:        &dpb.HiddenSegmentServicesResponse{},
			assertError: assert.NoError,
		},
		"only lookup service": {
			info: func(t *testing.T, ctrl *gomock.Controller) discovery.TopologyInformation {
				info := mock_discovery.NewMockTopologyInformation(ctrl)
				info.EXPECT().HiddenSegmentLookupAddresses().Return(
					[]*net.UDPAddr{
						xtest.MustParseUDPAddr(t, "10.1.0.1:30254"),
						xtest.MustParseUDPAddr(t, "10.1.0.2:30254"),
					},
					nil,
				)
				info.EXPECT().HiddenSegmentRegistrationAddresses()
				return info
			},
			want: &dpb.HiddenSegmentServicesResponse{
				Lookup: []*dpb.HiddenSegmentLookupServer{
					{Address: "10.1.0.1:30254"},
					{Address: "10.1.0.2:30254"},
				},
			},
			assertError: assert.NoError,
		},
		"only registration service": {
			info: func(t *testing.T, ctrl *gomock.Controller) discovery.TopologyInformation {
				info := mock_discovery.NewMockTopologyInformation(ctrl)
				info.EXPECT().HiddenSegmentLookupAddresses()
				info.EXPECT().HiddenSegmentRegistrationAddresses().Return(
					[]*net.UDPAddr{
						xtest.MustParseUDPAddr(t, "10.1.0.3:30254"),
						xtest.MustParseUDPAddr(t, "10.1.0.4:30254"),
					},
					nil,
				)
				return info
			},
			want: &dpb.HiddenSegmentServicesResponse{
				Registration: []*dpb.HiddenSegmentRegistrationServer{
					{Address: "10.1.0.3:30254"},
					{Address: "10.1.0.4:30254"},
				},
			},
			assertError: assert.NoError,
		},
		"both services": {
			info: func(t *testing.T, ctrl *gomock.Controller) discovery.TopologyInformation {
				info := mock_discovery.NewMockTopologyInformation(ctrl)
				info.EXPECT().HiddenSegmentLookupAddresses().Return(
					[]*net.UDPAddr{
						xtest.MustParseUDPAddr(t, "10.1.0.1:30254"),
						xtest.MustParseUDPAddr(t, "10.1.0.2:30254"),
					},
					nil,
				)
				info.EXPECT().HiddenSegmentRegistrationAddresses().Return(
					[]*net.UDPAddr{
						xtest.MustParseUDPAddr(t, "10.1.0.3:30254"),
						xtest.MustParseUDPAddr(t, "10.1.0.4:30254"),
					},
					nil,
				)
				return info
			},
			want: &dpb.HiddenSegmentServicesResponse{
				Lookup: []*dpb.HiddenSegmentLookupServer{
					{Address: "10.1.0.1:30254"},
					{Address: "10.1.0.2:30254"},
				},
				Registration: []*dpb.HiddenSegmentRegistrationServer{
					{Address: "10.1.0.3:30254"},
					{Address: "10.1.0.4:30254"},
				},
			},
			assertError: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			d := discovery.Topology{Information: tc.info(t, ctrl)}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			got, err := d.HiddenSegmentServices(ctx, nil)
			tc.assertError(t, err)
			sort.Slice(got.Lookup, func(i, j int) bool {
				return got.Lookup[i].Address < got.Lookup[j].Address
			})
			sort.Slice(got.Registration, func(i, j int) bool {
				return got.Registration[i].Address < got.Registration[j].Address
			})
			assert.Equal(t, tc.want, got)
		})
	}
}
