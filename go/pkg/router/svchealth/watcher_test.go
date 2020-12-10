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

package svchealth_test

import (
	"context"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/router/svchealth"
	"github.com/scionproto/scion/go/pkg/router/svchealth/mock_svchealth"
)

func TestWatcherDiscover(t *testing.T) {
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	initial := &topology.RWTopology{
		CS: topology.IDAddrMap{
			"cs1": topology.TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.IPv4(127, 0, 0, 1),
					Port: 42,
				},
				UnderlayAddress: &net.UDPAddr{
					IP:   net.IPv4(127, 0, 0, 1),
					Port: 30041,
				},
			},
			"cs2": topology.TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.IPv4(127, 0, 0, 2),
					Port: 42,
				},
				UnderlayAddress: &net.UDPAddr{
					IP:   net.IPv4(127, 0, 0, 2),
					Port: 30041,
				},
			},
		},
		SIG: map[string]topology.GatewayInfo{
			"sig1": {
				CtrlAddr: &topology.TopoAddr{
					SCIONAddress: &net.UDPAddr{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 43,
					},
					UnderlayAddress: &net.UDPAddr{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 30041,
					},
				},
			},
			"sig2": {
				CtrlAddr: &topology.TopoAddr{
					SCIONAddress: &net.UDPAddr{
						IP:   net.IPv4(127, 0, 0, 2),
						Port: 43,
					},
					UnderlayAddress: &net.UDPAddr{
						IP:   net.IPv4(127, 0, 0, 2),
						Port: 30041,
					},
				},
			},
		},
	}

	d := mock_svchealth.NewMockDiscoverer(mctrl)
	d.EXPECT().Discoverable(addr.SvcDS).AnyTimes().Return(false)
	w := svchealth.Watcher{
		Discoverer: d,
		Topology:   topology.FromRWTopology(initial),
	}

	// Only cs1 is healthy. sigs not discoverable.
	d.EXPECT().Discoverable(addr.SvcCS).Return(true)
	d.EXPECT().Discover(gomock.Any(), addr.SvcCS).Return(
		[]*net.UDPAddr{initial.CS["cs1"].SCIONAddress}, nil,
	)
	d.EXPECT().Discoverable(addr.SvcSIG).Return(false)

	diff, err := w.Discover(context.Background())
	require.NoError(t, err)
	require.Equal(t,
		svchealth.Diff{
			Add:    map[addr.HostSVC][]net.IP{},
			Remove: map[addr.HostSVC][]net.IP{addr.SvcCS: {initial.CS["cs2"].SCIONAddress.IP}},
		},
		diff,
	)

	// Only sig1 is healthy. cses not discoverable.
	d.EXPECT().Discoverable(addr.SvcCS).Return(false)
	d.EXPECT().Discoverable(addr.SvcSIG).Return(true)
	d.EXPECT().Discover(gomock.Any(), addr.SvcSIG).Return(
		[]*net.UDPAddr{initial.SIG["sig1"].CtrlAddr.SCIONAddress}, nil,
	)
	diff, err = w.Discover(context.Background())
	require.NoError(t, err)
	require.Equal(t,
		svchealth.Diff{
			Add: map[addr.HostSVC][]net.IP{addr.SvcCS: {initial.CS["cs2"].SCIONAddress.IP}},
			Remove: map[addr.HostSVC][]net.IP{
				addr.SvcSIG: {initial.SIG["sig2"].CtrlAddr.SCIONAddress.IP}},
		},
		diff,
	)

	// Discover fails for sig, fallback.
	d.EXPECT().Discoverable(addr.SvcCS).Return(true)
	d.EXPECT().Discover(gomock.Any(), addr.SvcCS).Return(
		[]*net.UDPAddr{initial.CS["cs1"].SCIONAddress, initial.CS["cs2"].SCIONAddress}, nil,
	)
	d.EXPECT().Discoverable(addr.SvcSIG).Return(true)
	d.EXPECT().Discover(gomock.Any(), addr.SvcSIG).Return(
		nil, serrors.New("internal"),
	)
	diff, err = w.Discover(context.Background())
	require.NoError(t, err)
	require.Equal(t,
		svchealth.Diff{
			Add: map[addr.HostSVC][]net.IP{addr.SvcSIG: {
				initial.SIG["sig2"].CtrlAddr.SCIONAddress.IP}},
			Remove: map[addr.HostSVC][]net.IP{},
		},
		diff,
	)

	// Discover returns no address, fallback.
	d.EXPECT().Discoverable(addr.SvcCS).Return(true)
	d.EXPECT().Discover(gomock.Any(), addr.SvcCS).Return(
		nil, nil,
	)
	d.EXPECT().Discoverable(addr.SvcSIG).Return(true)
	d.EXPECT().Discover(gomock.Any(), addr.SvcSIG).Return(
		nil, nil,
	)
	diff, err = w.Discover(context.Background())
	require.NoError(t, err)
	require.Equal(t,
		svchealth.Diff{
			Add:    map[addr.HostSVC][]net.IP{},
			Remove: map[addr.HostSVC][]net.IP{},
		},
		diff,
	)
}

func TestWatcherDiscoverNoSIG(t *testing.T) {
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	initial := &topology.RWTopology{
		CS: topology.IDAddrMap{
			"cs1": topology.TopoAddr{
				SCIONAddress: &net.UDPAddr{
					IP:   net.IPv4(127, 0, 0, 1),
					Port: 42,
				},
				UnderlayAddress: &net.UDPAddr{
					IP:   net.IPv4(127, 0, 0, 1),
					Port: 30041,
				},
			},
		},
	}

	d := mock_svchealth.NewMockDiscoverer(mctrl)
	d.EXPECT().Discoverable(addr.SvcDS).AnyTimes().Return(false)
	w := svchealth.Watcher{
		Discoverer: d,
		Topology:   topology.FromRWTopology(initial),
	}

	d.EXPECT().Discoverable(addr.SvcCS).Return(true)
	d.EXPECT().Discover(gomock.Any(), addr.SvcCS).Return(
		[]*net.UDPAddr{initial.CS["cs1"].SCIONAddress}, nil,
	)
	d.EXPECT().Discoverable(addr.SvcSIG).Return(false)

	diff, err := w.Discover(context.Background())
	require.NoError(t, err)
	require.Equal(t,
		svchealth.Diff{
			Add:    map[addr.HostSVC][]net.IP{},
			Remove: map[addr.HostSVC][]net.IP{},
		},
		diff,
	)
}
