// Copyright 2021 Anapaya Systems
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

package onehop

import (
	"context"
	"fmt"
	"hash"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	infraenv "github.com/scionproto/scion/private/app/appnet"
)

// Addr represents a service address in a remote ISD-AS reachable via a SCION onehop path.
type Addr struct {
	// IA is the ISD-AS identifier of the remote AS.
	IA addr.IA
	// Egress is the interface over which the remote AS should be reached.
	Egress uint16
	// SVC is the service anycast address of the designated service in the remote AS.
	SVC addr.SVC
	// NextHop is the router that owns the egress interface.
	NextHop *net.UDPAddr
}

func (a Addr) Network() string {
	return ""
}

func (a Addr) String() string {
	return fmt.Sprintf("%s#%d %s", a.IA, a.Egress, a.SVC)
}

// AddressRewriter is used to perform SVC resolution over a onehop path.
type AddressRewriter struct {
	// Rewriter is used to perform the SVC resolution.
	Rewriter *infraenv.AddressRewriter
	// MAC is the mac to issue hop fields.
	MAC hash.Hash
	// macMtx protects the MAC.
	macMtx sync.Mutex
}

func (r *AddressRewriter) RedirectToQUIC(
	ctx context.Context,
	address net.Addr,
) (net.Addr, error) {
	a, ok := address.(*Addr)
	if !ok {
		return r.Rewriter.RedirectToQUIC(ctx, address)
	}
	path, err := r.getPath(a.Egress)
	if err != nil {
		return nil, err
	}
	svc := &snet.SVCAddr{
		IA:      a.IA,
		Path:    path,
		SVC:     addr.SvcCS,
		NextHop: a.NextHop,
	}
	return r.Rewriter.RedirectToQUIC(ctx, svc)
}

func (r *AddressRewriter) getPath(egress uint16) (path.OneHop, error) {
	r.macMtx.Lock()
	defer r.macMtx.Unlock()

	return path.NewOneHop(egress, time.Now(), 63, r.MAC)
}
