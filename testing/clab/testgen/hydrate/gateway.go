// Copyright 2026 Anapaya Systems
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

package hydrate

import (
	"fmt"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// Gateway ports. The gateway runs on host-1, next to the control service and
// the daemon; these ports do not collide with theirs.
const (
	gatewayCtrlPort  = 30256
	gatewayDataPort  = 30056
	gatewayProbePort = 30856
	gatewayAPIPort   = 41400
)

// Gateway is a SCION IP gateway (SIG) on an AS's host-1. Each gateway owns an
// IPv4 prefix: the gateway host holds the first address of the prefix on its
// loopback interface, and the other gateways route the whole prefix through
// their tunnel to this gateway.
type Gateway struct {
	// IA is the ISD-AS of the gateway's AS.
	IA addr.IA
	ID string
	// Host is the name of the host that runs the gateway (host-1).
	Host      string
	CtrlAddr  netip.AddrPort
	DataAddr  netip.AddrPort
	ProbeAddr netip.AddrPort
	APIAddr   netip.AddrPort
	// Prefix is the IPv4 prefix behind this gateway.
	Prefix netip.Prefix
	// Addr is the address of the gateway host within Prefix. It is the source
	// of the traffic the host sends through the tunnel.
	Addr netip.Addr
	// Remotes are the gateways of all other ASes.
	Remotes []*Gateway
}

// AddGateways adds a [Gateway] to the first host (host-1) of every AS and
// connects every gateway to the gateways of all other ASes.
func AddGateways(n *Network, alloc Allocator) error {
	var gws []*Gateway
	for _, a := range n.ASes {
		ga, err := alloc.Gateway(a.IA)
		if err != nil {
			return serrors.Wrap("allocating gateway prefix", err, "as", a.IA)
		}
		h := a.Hosts[0]
		gw := &Gateway{
			IA:        a.IA,
			ID:        fmt.Sprintf("gw%s-1", addr.FormatIA(a.IA, addr.WithFileSeparator())),
			Host:      h.Name,
			CtrlAddr:  netip.AddrPortFrom(h.Addr, gatewayCtrlPort),
			DataAddr:  netip.AddrPortFrom(h.Addr, gatewayDataPort),
			ProbeAddr: netip.AddrPortFrom(h.Addr, gatewayProbePort),
			APIAddr:   netip.AddrPortFrom(h.Addr, gatewayAPIPort),
			Prefix:    ga.Prefix,
			Addr:      ga.Addr,
		}
		a.Gateway = gw
		h.Gateway = true
		gws = append(gws, gw)
	}
	for _, gw := range gws {
		for _, other := range gws {
			if other != gw {
				gw.Remotes = append(gw.Remotes, other)
			}
		}
	}
	return nil
}
