// Copyright 2024 Anapaya Systems
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

package daemon_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/mock_daemon"
	"github.com/scionproto/scion/pkg/snet"
)

func TestLoadTopology(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	conn := mock_daemon.NewMockConnector(ctrl)
	wantTopo := testTopology{
		ia:    addr.MustParseIA("1-ff00:0:110"),
		start: uint16(4096),
		end:   uint16(8192),
		interfaces: map[uint16]netip.AddrPort{
			1: netip.MustParseAddrPort("10.0.0.1:5153"),
			2: netip.MustParseAddrPort("10.0.0.2:6421"),
		},
	}
	wantTopo.setupMockResponses(conn)

	topo, err := daemon.LoadTopology(context.Background(), conn)
	assert.NoError(t, err)
	wantTopo.checkTopology(t, topo)
}

func TestReloadingTopology(t *testing.T) {
	ctrl := gomock.NewController(t)
	conn := mock_daemon.NewMockConnector(ctrl)

	wantTopo := testTopology{
		ia:    addr.MustParseIA("1-ff00:0:110"),
		start: uint16(4096),
		end:   uint16(8192),
		interfaces: map[uint16]netip.AddrPort{
			1: netip.MustParseAddrPort("10.0.0.1:5153"),
			2: netip.MustParseAddrPort("10.0.0.2:6421"),
		},
	}
	interfacesLater := map[uint16]netip.AddrPort{
		2: netip.MustParseAddrPort("10.0.0.2:6421"),
		3: netip.MustParseAddrPort("10.0.0.3:7539"),
	}
	calls := wantTopo.setupMockResponses(conn)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	gomock.InOrder(
		append(calls,
			conn.EXPECT().Interfaces(gomock.Any()).DoAndReturn(
				func(context.Context) (map[uint16]netip.AddrPort, error) {
					cancel()
					return interfacesLater, nil
				},
			).AnyTimes(),
		)...,
	)

	loader, err := daemon.NewReloadingTopology(ctx, conn)
	assert.NoError(t, err)
	topo := loader.Topology()
	wantTopo.checkTopology(t, topo)

	go func() {
		loader.Run(ctx, 100*time.Millisecond)
		close(done)
	}()
	<-done
	wantTopo.interfaces = interfacesLater
	wantTopo.checkTopology(t, loader.Topology())
	_, ok := loader.Topology().Interface(1)
	assert.False(t, ok)
}

type testTopology struct {
	ia         addr.IA
	start      uint16
	end        uint16
	interfaces map[uint16]netip.AddrPort
}

func (tt testTopology) setupMockResponses(c *mock_daemon.MockConnector) []*gomock.Call {
	return []*gomock.Call{
		c.EXPECT().LocalIA(gomock.Any()).Return(tt.ia, nil),
		c.EXPECT().PortRange(gomock.Any()).Return(tt.start, tt.end, nil),
		c.EXPECT().Interfaces(gomock.Any()).Return(tt.interfaces, nil),
	}
}

func (tt testTopology) checkTopology(t *testing.T, topo snet.Topology) {
	t.Helper()

	assert.Equal(t, tt.ia, topo.LocalIA)
	assert.Equal(t, tt.start, topo.PortRange.Start)
	assert.Equal(t, tt.end, topo.PortRange.End)
	for ifID, want := range tt.interfaces {
		got, ok := topo.Interface(ifID)
		assert.True(t, ok, "interface %d", ifID)
		assert.Equal(t, want, got, "interface %d", ifID)
	}
}
