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

package daemon

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

// LoadTopology loads the local topology from the given connector. The topology
// information is loaded once and does not update automatically.
func LoadTopology(ctx context.Context, conn Connector) (snet.Topology, error) {
	ia, err := conn.LocalIA(ctx)
	if err != nil {
		return snet.Topology{}, serrors.Wrap("loading local ISD-AS", err)
	}
	start, end, err := conn.PortRange(ctx)
	if err != nil {
		return snet.Topology{}, serrors.Wrap("loading port range", err)
	}
	interfaces, err := conn.Interfaces(ctx)
	if err != nil {
		return snet.Topology{}, serrors.Wrap("loading interfaces", err)
	}

	return snet.Topology{
		LocalIA: ia,
		PortRange: snet.TopologyPortRange{
			Start: start,
			End:   end,
		},
		Interface: func(ifID uint16) (netip.AddrPort, bool) {
			a, ok := interfaces[ifID]
			return a, ok
		},
	}, nil
}

// ReloadingTopology is a topology that reloads the interface information
// periodically. It is safe for concurrent use.
type ReloadingTopology struct {
	conn         Connector
	baseTopology snet.Topology
	interfaces   sync.Map
}

// NewReloadingTopology creates a new ReloadingTopology that reloads the
// interface information periodically. The Run method must be called for
// interface information to be populated.
func NewReloadingTopology(ctx context.Context, conn Connector) (*ReloadingTopology, error) {
	topo, err := LoadTopology(ctx, conn)
	if err != nil {
		return nil, err
	}
	return &ReloadingTopology{
		conn:         conn,
		baseTopology: topo,
	}, nil
}

func (t *ReloadingTopology) Topology() snet.Topology {
	base := t.baseTopology
	return snet.Topology{
		LocalIA:   base.LocalIA,
		PortRange: base.PortRange,
		Interface: func(ifID uint16) (netip.AddrPort, bool) {
			a, ok := t.interfaces.Load(ifID)
			if !ok {
				return netip.AddrPort{}, false
			}
			return a.(netip.AddrPort), true
		},
	}
}

func (t *ReloadingTopology) Run(ctx context.Context, period time.Duration) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	reload := func() {
		intfs, err := t.conn.Interfaces(ctx)
		if err != nil {
			log.FromCtx(ctx).Error("Failed to reload interfaces", "err", err)
		}
		for ifID, addr := range intfs {
			t.interfaces.Store(ifID, addr)
		}
	}

	reload()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reload()
		}
	}
}
