// Copyright 2019 Anapaya Systems
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

package trust

import (
	"context"
	"net"
	"time"

	"golang.org/x/xerrors"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

// Router builds the CS address for crypto material with the subject in a given ISD.
type Router interface {
	// ChooseServer determines the remote server for trust material with the
	// subject in the provided ISD.
	ChooseServer(ctx context.Context, subjectISD addr.ISD) (net.Addr, error)
}

type localRouter struct {
	ia addr.IA
}

// ChooseServer always routes to the local CS.
func (r *localRouter) ChooseServer(_ context.Context, _ addr.ISD) (net.Addr, error) {
	return r.chooseServer(), nil
}

func (r *localRouter) chooseServer() net.Addr {
	return &snet.Addr{IA: r.ia, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
}

type csRouter struct {
	isd    addr.ISD
	router snet.Router
	db     TRCRead
}

// ChooseServer builds a CS address for crypto with the subject in a given ISD.
//  * a local authoritative CS if subject is ISD-local.
//  * a local authoritative CS if subject is in remote ISD, but no active TRC is available.
//  * a remote authoritative CS otherwise.
func (r *csRouter) ChooseServer(ctx context.Context, subjectISD addr.ISD) (net.Addr, error) {
	dstISD, err := r.dstISD(ctx, subjectISD)
	if err != nil {
		return nil, serrors.WrapStr("unable to determine dest ISD to query", err)
	}
	path, err := r.router.Route(ctx, addr.IA{I: dstISD})
	if err != nil {
		return nil, serrors.WrapStr("unable to find path to any core AS", err, "isd", dstISD)
	}
	a := &snet.Addr{
		IA:      path.Destination(),
		Host:    addr.NewSVCUDPAppAddr(addr.SvcCS),
		Path:    path.Path(),
		NextHop: path.OverlayNextHop(),
	}
	return a, nil
}

// dstISD selects the CS to ask for crypto material, using the following strategy:
//  * a local authoritative CS if subject is ISD-local.
//  * a local authoritative CS if subject is in remote ISD, but no active TRC is available.
//  * a remote authoritative CS otherwise.
func (r *csRouter) dstISD(ctx context.Context, destination addr.ISD) (addr.ISD, error) {
	if destination == r.isd {
		return r.isd, nil
	}
	info, err := r.db.GetTRCInfo(ctx, destination, scrypto.Version(scrypto.LatestVer))
	if err != nil {
		if xerrors.Is(err, ErrNotFound) {
			return r.isd, nil
		}
		return 0, serrors.WrapStr("error querying DB for TRC", err)
	}
	if !info.Validity.Contains(time.Now()) {
		return r.isd, nil
	}
	return destination, nil
}
