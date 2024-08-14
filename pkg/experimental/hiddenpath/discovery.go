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

package hiddenpath

import (
	"context"
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

// Servers is a list of discovered remote hidden segment server.
type Servers struct {
	// Lookup is the list of lookup addresses.
	Lookup []*net.UDPAddr
	// Registration is the list of registration addresses.
	Registration []*net.UDPAddr
}

// Discoverer can be used to find remote discovery services.
type Discoverer interface {
	Discover(ctx context.Context, dsAddr net.Addr) (Servers, error)
}

// AddressResolver helps to resolve addresses in a remote AS.
type AddressResolver interface {
	// Resolve creates an address with a path to the remote ISD-AS that is
	// specified.
	Resolve(context.Context, addr.IA) (net.Addr, error)
}

// RegistrationResolver resolves the address of a hidden segment registration
// server in an IA.
type RegistrationResolver struct {
	Router     snet.Router
	Discoverer Discoverer
}

// Resolve resolves a hidden segment registration server in the remote IA.
func (r RegistrationResolver) Resolve(ctx context.Context, ia addr.IA) (net.Addr, error) {
	return resolve(ctx, ia, r.Discoverer, r.Router, func(s Servers) (*net.UDPAddr, error) {
		if len(s.Registration) == 0 {
			return nil, serrors.New("no registration server found")
		}
		return s.Registration[0], nil
	})
}

// LookupResolver resolves the address of a hidden segment lookup
// server in an IA.
type LookupResolver struct {
	Router     snet.Router
	Discoverer Discoverer
}

// Resolve resolves a hidden segment lookup server in the remote IA.
func (r LookupResolver) Resolve(ctx context.Context, ia addr.IA) (net.Addr, error) {
	return resolve(ctx, ia, r.Discoverer, r.Router, func(s Servers) (*net.UDPAddr, error) {
		if len(s.Lookup) == 0 {
			return nil, serrors.New("no lookup server found")
		}
		return s.Lookup[0], nil
	})
}

func resolve(ctx context.Context, ia addr.IA, discoverer Discoverer, router snet.Router,
	extractAddr func(Servers) (*net.UDPAddr, error)) (net.Addr, error) {

	p, err := router.Route(ctx, ia)
	if err != nil {
		return nil, serrors.Wrap("looking up path", err)
	}
	if p == nil {
		return nil, serrors.Wrap("no path found to remote", err)
	}
	dsAddr := &snet.SVCAddr{
		IA:      ia,
		NextHop: p.UnderlayNextHop(),
		Path:    p.Dataplane(),
		SVC:     addr.SvcDS,
	}
	if dsAddr.Path == nil {
		dsAddr.Path = path.Empty{}
	}
	hps, err := discoverer.Discover(ctx, dsAddr)
	if err != nil {
		return nil, serrors.Wrap("discovering hidden path server", err)
	}
	a, err := extractAddr(hps)
	if err != nil {
		return nil, serrors.Wrap("extracting address", err, "isd_as", ia)
	}
	return &snet.UDPAddr{
		IA:      ia,
		Host:    a,
		NextHop: dsAddr.NextHop,
		Path:    dsAddr.Path,
	}, nil
}
