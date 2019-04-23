// Copyright 2019 ETH Zurich
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

package snet

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/spath"
)

// Router performs path resolution for SCION-speaking applications.
//
// Most applications backed by SCIOND can use the default router implementation
// in this package. Applications that run SCIOND-less (PS, SD, BS) might be
// interested in spinning their own implementations.
type Router interface {
	// Route returns a path from the local AS to dst.
	Route(ctx context.Context, dst addr.IA) (Path, error)
	// LocalIA returns the IA from which this router routes.
	LocalIA() addr.IA
}

// Path is an abstract representation of a path. Most applications do not need
// access to the raw internals.
type Path interface {
	// OverlayNextHop returns the address:port pair of a local-AS overlay
	// speaker. Usually, this is a border router that will forward the traffic.
	OverlayNextHop() *overlay.OverlayAddr
	// Path returns a raw (data-plane compatible) representation of the path.
	// The returned path is initialized and ready for use in snet calls that
	// deal with raw paths.
	Path() *spath.Path
}

// LocalMachine describes aspects of the host system and its network.
type LocalMachine struct {
	// InterfaceIP is the default L3 address for connections originating from
	// this machine. It should be an address configured on a host interface
	// that is reachable from the network.
	InterfaceIP net.IP
	// If this machine is behind a NAT, PublicIP should be set to the public IP
	// of the NAT. If the local IP is already public, PublicIP should be set to
	// nil.
	PublicIP net.IP
}

// AppAddress returns a public address for the local machine. The port is
// set to 0.
func (m *LocalMachine) AppAddress() *addr.AppAddr {
	ip := m.InterfaceIP
	if m.PublicIP != nil {
		ip = m.PublicIP
	}
	return &addr.AppAddr{
		L3: addr.HostFromIP(ip),
		L4: addr.NewL4UDPInfo(0),
	}
}

// BindAddress returns a bind address for the local machine. The port is
// set to 0.
func (m *LocalMachine) BindAddress() *overlay.OverlayAddr {
	ov, err := overlay.NewOverlayAddr(
		addr.HostFromIP(m.InterfaceIP),
		addr.NewL4UDPInfo(0),
	)
	if err != nil {
		// XXX(scrye): due to the hardcoded types in this function, this should
		// never panic
		panic(err)
	}
	return ov
}
