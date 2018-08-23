// Copyright 2018 Anapaya Systems
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

package handlers

import (
	"bytes"
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/infra/modules/segsaver"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/pathdb/conn"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	HandlerTimeout = 3 * time.Second
)

// HandlerArgs are the values required to create the path server's handlers.
type HandlerArgs struct {
	PathDB     conn.Conn
	RevCache   revcache.RevCache
	TrustStore infra.TrustStore
	Topology   *topology.Topo
}

type baseHandler struct {
	request    *infra.Request
	pathDB     conn.Conn
	revCache   revcache.RevCache
	trustStore infra.TrustStore
	topology   *topology.Topo
	logger     log.Logger
}

func newBaseHandler(request *infra.Request, args *HandlerArgs) *baseHandler {
	return &baseHandler{
		request:    request,
		pathDB:     args.PathDB,
		revCache:   args.RevCache,
		trustStore: args.TrustStore,
		topology:   args.Topology,
		logger:     request.Logger,
	}
}

// fetchSegsFromDB gets segments from the path DB and filters revoked segments.
func (h *baseHandler) fetchSegsFromDB(ctx context.Context,
	params *query.Params) ([]*seg.PathSegment, error) {

	res, err := h.pathDB.Get(ctx, params)
	if err != nil {
		return nil, err
	}
	segs := extractSegs(res)
	// XXX(lukedirtwalker): Consider cases where segment with revoked interfaces should be returned.
	return filterSegs(segs, h.noRevokedHopIntf), nil
}

// noRevokedHopIntf returns true if there is no revoked on-segment interface on the segment s.
func (h *baseHandler) noRevokedHopIntf(s *seg.PathSegment) bool {
	revKeys := make(map[revcache.Key]struct{})
	addRevKeys([]*seg.PathSegment{s}, revKeys, true)
	for rk := range revKeys {
		if _, ok := h.revCache.Get(&rk); ok {
			return false
		}
	}
	return true
}

func (h *baseHandler) addrFromPath(path *combinator.Path, dstIA addr.IA) (net.Addr, error) {
	nextHop, ok := h.topology.IFInfoMap[path.Interfaces[0].IfID]
	if !ok {
		h.logger.Warn("Unable to find first-hop BR for path", "ifid", path.Interfaces[0].IfID)
		return nil, common.NewBasicError("Unable to find first-hop BR for path", nil)
	}
	pAddr := nextHop.InternalAddr.PublicAddr(h.topology.Overlay)
	x := &bytes.Buffer{}
	_, err := path.WriteTo(x)
	if err != nil {
		// In-memory write should never fail
		panic(err)
	}
	p := spath.New(x.Bytes())
	if err = p.InitOffsets(); err != nil {
		return nil, err
	}
	nhAddr, err := overlay.NewOverlayAddr(pAddr.L3, pAddr.L4)
	if err != nil {
		return nil, err
	}
	return &snet.Addr{
		IA: dstIA,
		Host: &addr.AppAddr{
			L3: addr.SvcPS,
			L4: addr.NewL4UDPInfo(0),
		},
		Path:    p,
		NextHop: nhAddr,
	}, nil
}

// ignore is a convenience function that can be passed into verifyAndStore if no further action
// should be taken when a segment was verified.
func ignore(context.Context, *seg.Meta) {}

func (h *baseHandler) verifyAndStore(ctx context.Context, src net.Addr,
	segVerified func(context.Context, *seg.Meta),
	recs []*seg.Meta, revInfos []*path_mgmt.SignedRevInfo) {
	// TODO(lukedirtwalker): collect the verified segs/revoc and return them.

	// verify and store the segments
	verifiedSeg := func(ctx context.Context, s *seg.Meta) {
		segVerified(ctx, s)
		if err := segsaver.StoreSeg(ctx, s, h.pathDB, h.logger); err != nil {
			h.logger.Error("Unable to insert segment into path database",
				"seg", s.Segment, "err", err)
		}
	}
	verifiedRev := func(ctx context.Context, rev *path_mgmt.SignedRevInfo) {
		segsaver.StoreRevocation(rev, h.revCache)
	}
	segErr := func(s *seg.Meta, err error) {
		h.logger.Warn("Segment verification failed", "segment", s.Segment, "err", err)
	}
	revErr := func(revocation *path_mgmt.SignedRevInfo, err error) {
		h.logger.Warn("Revocation verification failed", "revocation", revocation, "err", err)
	}
	segverifier.Verify(ctx, h.trustStore, src, recs,
		revInfos, verifiedSeg, verifiedRev, segErr, revErr)
}

func filterSegs(segs []*seg.PathSegment, keep func(*seg.PathSegment) bool) []*seg.PathSegment {
	filtered := segs[:0]
	for _, s := range segs {
		if keep(s) {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// XXX(lukedirtwalker): this code is also in fetcher (inside getSegmentsFromDB)
func extractSegs(res []*query.Result) []*seg.PathSegment {
	segs := make([]*seg.PathSegment, len(res))
	for i, r := range res {
		segs[i] = r.Seg
	}
	return segs
}

func firstIA(s *seg.PathSegment) addr.IA { return s.FirstIA() }

// XXX(lukedirtwalker): this code is also in fetcher (getStartIAs)
func firstIAs(segs []*seg.PathSegment) []addr.IA {
	return extractIAs(segs, firstIA)
}

func lastIA(s *seg.PathSegment) addr.IA { return s.LastIA() }

func lastIAs(segs []*seg.PathSegment) []addr.IA {
	return extractIAs(segs, lastIA)
}

func extractIAs(segs []*seg.PathSegment, extract func(*seg.PathSegment) addr.IA) []addr.IA {
	var empty struct{}
	var ias []addr.IA
	addrs := make(map[addr.IA]struct{})
	for _, s := range segs {
		ia := extract(s)
		if _, ok := addrs[ia]; !ok {
			addrs[ia] = empty
			ias = append(ias, ia)
		}
	}
	return ias
}
