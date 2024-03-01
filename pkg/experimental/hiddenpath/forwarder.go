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
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/segment/segverifier"
	infra "github.com/scionproto/scion/private/segment/verifier"
)

// Lookuper is used to lookup segments.
type Lookuper interface {
	Segments(context.Context, SegmentRequest) ([]*seg.Meta, error)
}

// RPC is used to fetch hidden segments from a remote and to register segments to a remote.
type RPC interface {
	HiddenSegments(context.Context, SegmentRequest, net.Addr) ([]*seg.Meta, error)
}

// Verifier is used to verify a segments reply.
type Verifier interface {
	// Verify fetches the crypto material from the server and verifies the segments.
	Verify(ctx context.Context, segments []*seg.Meta, server net.Addr) error
}

// ForwardServer handles hidden path segment lookup requests from daemons.
// For each group id of the request, it requests the segments at the the
// respective autoritative registry.
type ForwardServer struct {
	Groups     map[GroupID]*Group
	LocalAuth  Lookuper
	LocalIA    addr.IA
	RPC        RPC
	HPResolver AddressResolver
	CSResolver AddressResolver
	Verifier   Verifier
}

// Segments serves segments for the given request. It finds per group ID
// the authoritative server and makes the QUIC grpc call. It does not support
// local cache.
func (s ForwardServer) Segments(ctx context.Context,
	req SegmentRequest) ([]*seg.Meta, error) {

	if len(req.GroupIDs) == 0 {
		return nil, serrors.New("no group IDs provided")
	}
	requests := make(map[addr.IA][]GroupID)
	for _, id := range req.GroupIDs {
		group, ok := s.Groups[id]
		if !ok {
			return nil, serrors.New("request for unknown group", "group", id)
		}
		regs := group.GetRegistries()
		if len(regs) == 0 {
			return nil, serrors.New("no registry was found", "group", id)
		}
		// XXX(karampok): we just pick the first one. In the future we have
		// to support array with failover approach, if the first one errors,
		// try the second etc.
		key := regs[0]
		if v, ok := requests[key]; ok {
			requests[key] = append(v, id)
			continue
		}
		requests[key] = []GroupID{id}
	}

	type segsOrErr struct {
		segs []*seg.Meta
		err  error
	}

	replies := make(chan segsOrErr, len(requests))
	for registry, groups := range requests {
		go func(r addr.IA, g []GroupID) {
			defer log.HandlePanic()

			req := SegmentRequest{
				GroupIDs: g,
				DstIA:    req.DstIA,
			}
			if r.Equal(s.LocalIA) {
				req.Peer = s.LocalIA
				reply, err := s.LocalAuth.Segments(ctx, req)
				replies <- segsOrErr{segs: reply, err: err}
				return
			}
			a, err := s.HPResolver.Resolve(ctx, r)
			if err != nil {
				replies <- segsOrErr{err: err}
				return
			}
			reply, err := s.RPC.HiddenSegments(ctx, req, a)
			if err != nil {
				replies <- segsOrErr{err: err}
				return
			}
			a, err = s.CSResolver.Resolve(ctx, r)
			if err != nil {
				replies <- segsOrErr{err: err}
				return
			}
			if err := s.Verifier.Verify(ctx, reply, a); err != nil {
				replies <- segsOrErr{
					err: serrors.WrapStr("verifying segment", err, "crypto-source", r,
						"server", a),
				}
				return
			}
			replies <- segsOrErr{segs: reply}
		}(registry, groups)
	}

	var (
		segs []*seg.Meta
		errs serrors.List
	)
	for range requests {
		reply := <-replies
		if e := reply.err; e != nil {
			errs = append(errs, e)
			continue
		}
		segs = append(segs, reply.segs...)
	}
	return segs, errs.ToError()
}

// VerifierAdapter adapts and infra.Verifier to the hidden path verifier
// interface.
type VerifierAdapter struct {
	Verifier infra.Verifier
}

// Verify verifies the segments. It returns an error if a verification of any of
// the segments fails.
func (v VerifierAdapter) Verify(ctx context.Context, segments []*seg.Meta, server net.Addr) error {
	resCh, units := segverifier.StartVerification(ctx, v.Verifier, server, segments)

	var errors serrors.List
	for u := 0; u < units; u++ {
		vu := <-resCh
		if err := vu.SegError(); err != nil {
			errors = append(errors, err)
		}
	}
	return errors.ToError()
}
