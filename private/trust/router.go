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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/snet"
)

// Router builds the CS address for crypto material with the subject in a given ISD.
type Router interface {
	// ChooseServer determines the remote server for trust material with the
	// subject in the provided ISD.
	ChooseServer(ctx context.Context, subjectISD addr.ISD) (net.Addr, error)
}

// LocalRouter routes requests to the local CS.
type LocalRouter struct {
	IA addr.IA
}

// ChooseServer always routes to the local CS.
func (r LocalRouter) ChooseServer(_ context.Context, _ addr.ISD) (net.Addr, error) {
	return r.chooseServer(), nil
}

func (r LocalRouter) chooseServer() net.Addr {
	return &snet.SVCAddr{IA: r.IA, SVC: addr.SvcCS}
}

// AuthRouter routes requests for missing crypto material to the authoritative
// ASes of the appropriate ISD.
//
// TODO(roosd): Add implementation of snet.Router that routes to authoritative AS.
type AuthRouter struct {
	ISD    addr.ISD
	Router snet.Router
	DB     DB
}

// ChooseServer builds a CS address for crypto with the subject in a given ISD.
//   - a local authoritative CS if subject is ISD-local.
//   - a local authoritative CS if subject is in remote ISD, but no active TRC is available.
//   - a remote authoritative CS otherwise.
func (r AuthRouter) ChooseServer(ctx context.Context, subjectISD addr.ISD) (net.Addr, error) {
	dstISD, err := r.dstISD(ctx, subjectISD)
	if err != nil {
		return nil, serrors.WrapStr("unable to determine dest ISD to query", err)
	}
	logger := log.FromCtx(ctx)
	logger.Debug("Getting paths to any authoritative server", "isd", dstISD)
	path, err := r.Router.Route(ctx, addr.MustIAFrom(dstISD, 0))
	if err != nil || path == nil {
		return nil, serrors.WrapStr("unable to find path to any core AS", err, "isd", dstISD)
	}
	ret := &snet.SVCAddr{
		IA:      path.Destination(),
		Path:    path.Dataplane(),
		NextHop: path.UnderlayNextHop(),
		SVC:     addr.SvcCS,
	}
	return ret, nil
}

func (r AuthRouter) dstISD(ctx context.Context, destination addr.ISD) (addr.ISD, error) {
	if destination == r.ISD {
		return r.ISD, nil
	}
	logger := log.FromCtx(ctx)
	sTRC, err := r.DB.SignedTRC(ctx, cppki.TRCID{ISD: destination})
	if err != nil {
		return 0, serrors.WrapStr("error querying DB for TRC", err)
	}
	if sTRC.IsZero() {
		logger.Info("Direct to ISD-local authoritative servers",
			"reason", "remote TRC not found")
		return r.ISD, nil
	}
	if !sTRC.TRC.Validity.Contains(time.Now()) {
		logger.Info("Direct to ISD-local authoritative servers",
			"reason", "remote TRC outside of validity period")
		return r.ISD, nil
	}
	return destination, nil
}
