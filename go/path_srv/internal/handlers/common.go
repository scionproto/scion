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
	"fmt"
	"net"
	"strings"
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

type baseHandler struct {
	request    *infra.Request
	pathDB     conn.Conn
	revCache   revcache.RevCache
	trustStore infra.TrustStore
	topology   *topology.Topo
	logger     log.Logger
}

// dbSegs gets segments from the path DB and filters revoked segments.
func (h *baseHandler) dbSegs(ctx context.Context,
	params *query.Params) ([]*seg.PathSegment, error) {

	res, err := h.pathDB.Get(ctx, params)
	if err != nil {
		return nil, err
	}
	segs := extractSegs(res)
	return filterSegs(segs, h.noRevokedInterface), nil
}

// noRevokedInterface returns true if there is no revoked interface on the path segment seg.
func (h *baseHandler) noRevokedInterface(seg *seg.PathSegment) bool {
	rks := revKeys(seg)
	for _, rk := range rks {
		if _, ok := h.revCache.Get(rk); ok {
			return false
		}
	}
	return true
}

func (h *baseHandler) addrFromPath(paths []*combinator.Path, dstIA addr.IA) (net.Addr, error) {
	path := paths[0]
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

// revKeys returns the revocation keys for the given path segment.
func revKeys(seg *seg.PathSegment) []*revcache.Key {
	ifaces := onSegmentInterfaces(seg)
	keys := make([]*revcache.Key, 0, len(ifaces))
	for _, intf := range ifaces {
		keys = append(keys, revcache.NewKey(intf.IA, intf.IFID))
	}
	return keys
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

// print helper
func segRecs(sr *path_mgmt.SegRecs) string {
	desc := []string{"Recs:"}
	for _, m := range sr.Recs {
		desc = append(desc, fmt.Sprintf("%v: %v", m.Type, hopDesc(&m.Segment)))
	}
	if len(sr.SRevInfos) > 0 {
		desc = append(desc, "RevInfos")
		for _, info := range sr.SRevInfos {
			desc = append(desc, revInfo(info))
		}
	}
	return strings.Join(desc, "\n")
}

// print helper
func revInfo(rv *path_mgmt.SignedRevInfo) string {
	i, err := rv.RevInfo()
	if err != nil {
		return fmt.Sprintf("unable to get revInfo: %v", err)
	}
	return i.String()
}

// print helper
func hopDesc(ps *seg.PathSegment) string {
	hopsDesc := []string{}
	for _, ase := range ps.ASEntries {
		hopEntry := ase.HopEntries[0]
		hop, err := hopEntry.HopField()
		if err != nil {
			hopsDesc = append(hopsDesc, err.Error())
			continue
		}
		hopDesc := []string{}
		if hop.ConsIngress > 0 {
			hopDesc = append(hopDesc, fmt.Sprintf("%v ", hop.ConsIngress))
		}
		hopDesc = append(hopDesc, ase.IA().String())
		if hop.ConsEgress > 0 {
			hopDesc = append(hopDesc, fmt.Sprintf(" %v", hop.ConsEgress))
		}
		hopsDesc = append(hopsDesc, strings.Join(hopDesc, ""))
	}
	return strings.Join(hopsDesc, ">")
}

type segInterface struct {
	IA   addr.IA
	IFID common.IFIDType
}

var empty struct{}

// onSegmentInterfaces returns all segInterfaces that are on the segments hopfields
// (no peer interfaces).
func onSegmentInterfaces(s *seg.PathSegment) []*segInterface {
	ifaces := make([]*segInterface, 0, 2*len(s.ASEntries))
	for _, asEntry := range s.ASEntries {
		if len(asEntry.HopEntries) > 0 {
			entry := asEntry.HopEntries[0]
			hf, err := entry.HopField()
			if err != nil {
				// This should not happen, as Validate already checks that it
				// is possible to extract the hop field.
				panic(err)
			}
			if hf.ConsIngress != 0 {
				ifaces = append(ifaces, &segInterface{asEntry.IA(), hf.ConsIngress})
			}
			if hf.ConsEgress != 0 {
				ifaces = append(ifaces, &segInterface{asEntry.IA(), hf.ConsEgress})
			}
		}
	}
	return ifaces
}
