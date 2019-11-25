// Copyright 2019 ETH Zurich, Anapaya Systems
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
)

type PathQuerier interface {
	Query(context.Context, addr.IA) ([]Path, error)
}

// Router performs path resolution for SCION-speaking applications.
//
// Most applications backed by SCIOND can use the default router implementation
// in this package. Applications that run SCIOND-less (PS, SD, BS) might be
// interested in spinning their own implementations.
type Router interface {
	// Route returns a path from the local AS to dst. If dst matches the local
	// AS, an empty path is returned.
	Route(ctx context.Context, dst addr.IA) (Path, error)
	// AllRoutes is similar to Route except that it returns multiple paths.
	AllRoutes(ctx context.Context, dst addr.IA) ([]Path, error)
}

type BaseRouter struct {
	Querier PathQuerier
}

// Route uses the specified path resolver (if one exists) to obtain a path from
// the local AS to dst.
func (r *BaseRouter) Route(ctx context.Context, dst addr.IA) (Path, error) {
	paths, err := r.AllRoutes(ctx, dst)
	if err != nil {
		return nil, err
	}
	return paths[0], nil
}

// AllRoutes is the same as Route except that it returns multiple paths.
func (r *BaseRouter) AllRoutes(ctx context.Context, dst addr.IA) ([]Path, error) {
	return r.Querier.Query(ctx, dst)
}

// IntraASPathQuerier implements the PathQuerier interface. It will only provide
// AS internal paths, i.e., empty paths with only the IA as destination. This
// should only be used in places where you know that you only need to
// communicate inside the AS.
type IntraASPathQuerier struct {
	IA addr.IA
}

// Query implements PathQuerier.
func (q IntraASPathQuerier) Query(_ context.Context, _ addr.IA) ([]Path, error) {
	return []Path{&partialPath{destination: q.IA}}, nil
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
	}
}

// BindAddress returns a bind address for the local machine. The port is
// set to 0.
func (m *LocalMachine) BindAddress() *net.UDPAddr {
	return &net.UDPAddr{IP: m.InterfaceIP}
}
