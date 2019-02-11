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
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/dedupe"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/path_srv/internal/segutil"
	"github.com/scionproto/scion/go/proto"
)

const (
	maxResSegs = 10 // Maximum total of segments returned in a reply to a segment request
)

type segReqHandler struct {
	*baseHandler
	localIA     addr.IA
	segsDeduper dedupe.Deduper
}

func (h *segReqHandler) sendEmptySegReply(ctx context.Context,
	segReq *path_mgmt.SegReq, msger infra.Messenger) {

	msger.SendSegReply(ctx, &path_mgmt.SegReply{Req: segReq, Recs: nil},
		h.request.Peer, h.request.ID)
}

// isValidDst returns true if segReq contains a valid destination for segReq handlers,
// false otherwise.
func (h *segReqHandler) isValidDst(segReq *path_mgmt.SegReq) bool {
	// No validation on source here!
	if segReq.DstIA().IsZero() || segReq.DstIA().I == 0 || segReq.DstIA().Equal(h.localIA) {
		logger := log.FromCtx(h.request.Context())
		logger.Warn("[segReqHandler] Drop, invalid dstIA", "dstIA", segReq.DstIA())
		return false
	}
	return true
}

func (h *segReqHandler) isCoreDst(ctx context.Context, msger infra.Messenger,
	segReq *path_mgmt.SegReq) (bool, error) {

	if segReq.DstIA().A == 0 {
		return true, nil
	}
	dstTRC, err := h.trustStore.GetTRC(ctx, segReq.DstIA().I, scrypto.LatestVer)
	if err != nil {
		return false, common.NewBasicError("Failed to get TRC for dst", err)
	}
	return dstTRC.CoreASes.Contains(segReq.DstIA()), nil
}

func (h *segReqHandler) coreASes(ctx context.Context) (trc.CoreASMap, error) {
	srcTRC, err := h.trustStore.GetTRC(ctx, h.localIA.I, scrypto.LatestVer)
	if err != nil {
		return nil, common.NewBasicError("Failed to get TRC for localIA", err)
	}
	return srcTRC.CoreASes, nil
}

func (h *segReqHandler) fetchDownSegs(ctx context.Context, msger infra.Messenger,
	dst addr.IA, cPSAddr func() (net.Addr, error), dbOnly bool) (seg.Segments, error) {

	// try local cache first
	q := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_down},
		EndsAt:   []addr.IA{dst},
	}
	segs, err := h.fetchSegsFromDB(ctx, q)
	if err != nil {
		return nil, err
	}
	if dbOnly || len(segs) > 0 {
		refetch := !dbOnly
		if !dbOnly {
			refetch, err = h.shouldRefetchSegsForDst(ctx, dst, time.Now())
			if err != nil {
				log.FromCtx(ctx).Warn("[segReqHandler] failed to get last query", "err", err)
			}
		}
		if !refetch {
			return segs, nil
		}
	}
	cAddr, err := cPSAddr()
	if err != nil {
		return nil, err
	}
	logger := log.FromCtx(ctx)
	logger.Debug("[segReqHandler] Fetch down segments", "dst", dst, "remote", cAddr)
	if err = h.fetchAndSaveSegs(ctx, msger, addr.IA{}, dst, cAddr); err != nil {
		return nil, err
	}
	// TODO(lukedirtwalker): if fetchAndSaveSegs returns verified segs we don't need to query.
	return h.fetchSegsFromDB(ctx, q)
}

func (h *segReqHandler) fetchAndSaveSegs(ctx context.Context, msger infra.Messenger,
	src, dst addr.IA, cPSAddr net.Addr) error {

	logger := log.FromCtx(ctx)
	queryTime := time.Now()
	r := &path_mgmt.SegReq{RawSrcIA: src.IAInt(), RawDstIA: dst.IAInt()}
	// The logging below is used for acceptance testing do not delete!
	if snetAddr, ok := cPSAddr.(*snet.Addr); ok {
		logger.Trace("[segReqHandler] Sending segment request", "NextHop", snetAddr.NextHop)
	}
	segs, err := h.getSegsFromNetwork(ctx, r, cPSAddr, messenger.NextId())
	if err != nil {
		return err
	}
	segs = segs.Sanitize(logger)
	var recs []*seg.Meta
	var revInfos []*path_mgmt.SignedRevInfo
	if segs.Recs != nil {
		logSegRecs(logger, "[segReqHandler]", cPSAddr, segs.Recs)
		recs = segs.Recs.Recs
		revInfos, err = revcache.FilterNew(ctx, h.revCache, segs.Recs.SRevInfos)
		if err != nil {
			logger.Error("[segReqHandler] Failed to filter new revocations", "err", err)
			// in case of error we just assume all of them are new and continue.
			revInfos = segs.Recs.SRevInfos
		}
		h.verifyAndStore(ctx, cPSAddr, recs, revInfos)
		// TODO(lukedirtwalker): If we didn't receive anything we should retry earlier.
		if _, err := h.pathDB.InsertNextQuery(ctx, dst,
			queryTime.Add(h.config.QueryInterval.Duration)); err != nil {
			logger.Warn("Failed to insert last queried", "err", err)
		}
	}
	return nil
}

func (h *segReqHandler) getSegsFromNetwork(ctx context.Context,
	req *path_mgmt.SegReq, server net.Addr, id uint64) (*path_mgmt.SegReply, error) {

	responseC, cancelF := h.segsDeduper.Request(ctx, &segReq{
		segReq: req,
		server: server,
		id:     id,
	})
	defer cancelF()
	select {
	case response := <-responseC:
		if response.Error != nil {
			return nil, response.Error
		}
		return response.Data.(*path_mgmt.SegReply), nil
	case <-ctx.Done():
		return nil, common.NewBasicError("Context done while waiting for Segs", ctx.Err())
	}
}

func (h *segReqHandler) sendReply(ctx context.Context, msger infra.Messenger,
	upSegs, coreSegs, downSegs []*seg.PathSegment, segReq *path_mgmt.SegReq) {

	logger := log.FromCtx(ctx)
	revs, err := segutil.RelevantRevInfos(ctx, h.revCache, upSegs, coreSegs, downSegs)
	if err != nil {
		logger.Error("[segReqHandler] Failed to find relevant revocations for reply", "err", err)
		// the client might still be able to use the segments so continue here.
	}
	recs := &path_mgmt.SegRecs{
		Recs:      h.collectSegs(upSegs, coreSegs, downSegs),
		SRevInfos: revs,
	}
	reply := &path_mgmt.SegReply{
		Req:  segReq,
		Recs: recs,
	}
	err = msger.SendSegReply(ctx, reply, h.request.Peer, h.request.ID)
	if err != nil {
		logger.Error("[segReqHandler] Failed to send reply!", "err", err)
	}
	logger.Debug("[segReqHandler] reply sent", "id", h.request.ID,
		"ups", len(upSegs), "cores", len(coreSegs), "downs", len(downSegs))
}

func (h *segReqHandler) collectSegs(upSegs, coreSegs, downSegs []*seg.PathSegment) []*seg.Meta {
	logger := log.FromCtx(h.request.Context())
	recs := make([]*seg.Meta, 0, len(upSegs)+len(coreSegs)+len(downSegs))
	for i := range upSegs {
		s := upSegs[i]
		logger.Trace(fmt.Sprintf("[segReqHandler:collectSegs] up %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs = append(recs, seg.NewMeta(s, proto.PathSegType_up))
	}
	for i := range coreSegs {
		s := coreSegs[i]
		logger.Trace(fmt.Sprintf("[segReqHandler:collectSegs] core %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs = append(recs, seg.NewMeta(s, proto.PathSegType_core))
	}
	for i := range downSegs {
		s := downSegs[i]
		logger.Trace(fmt.Sprintf("[segReqHandler:collectSegs] down %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs = append(recs, seg.NewMeta(s, proto.PathSegType_down))
	}
	return recs
}

// shouldRefetchSegsForDst returns true if the segments for the given dst
// should be fetched from the remote PS. Returns true on error, so the value can be used anyway.
func (h *segReqHandler) shouldRefetchSegsForDst(ctx context.Context, dst addr.IA,
	now time.Time) (bool, error) {

	nq, err := h.pathDB.GetNextQuery(ctx, dst)
	if err != nil {
		return true, err
	}
	if nq == nil {
		return true, nil
	}
	return now.After(*nq), nil
}

// segsToMap converts the segs slice to a map of IAs to segments.
// The IA (key) is selected using the key function.
func segsToMap(segs []*seg.PathSegment,
	key func(*seg.PathSegment) addr.IA) map[addr.IA]struct{} {

	res := make(map[addr.IA]struct{})
	for _, s := range segs {
		res[key(s)] = struct{}{}
	}
	return res
}

// Combination of up, core and down segments (aka a Path).
type connectedSegs struct {
	Up, Core, Down *seg.PathSegment
}

func (p *connectedSegs) numHops() int {

	n := 0
	if p.Up != nil {
		n += len(p.Up.ASEntries)
	}
	if p.Core != nil {
		n += len(p.Core.ASEntries)
	}
	if p.Down != nil {
		n += len(p.Down.ASEntries)
	}
	return n
}

// Filter upSegs, coreSegs and downSegs to include at most maxNumSegments segments. Ensures that the remaining segments can be connected to allow forming paths between srcIA and dstIA.
func selectConnectedSegs(maxNumSegments int, upSegs, coreSegs, downSegs *seg.Segments, srcIA, dstIA addr.IA) {

	plen := func(s *seg.Segments) int {
		if s != nil {
			return len(*s)
		}
		return 0
	}

	if plen(upSegs)+plen(coreSegs)+plen(downSegs) < maxNumSegments {
		return
	}

	paths := allConnectedSegs(upSegs, coreSegs, downSegs, srcIA, dstIA)
	// Sort by least number of hops for path
	sort.Slice(paths, func(i, j int) bool {
		return paths[i].numHops() < paths[j].numHops()
	})

	selSegs := make(map[*seg.PathSegment]struct{})
	for _, path := range paths {
		if len(selSegs) > maxNumSegments-3 {
			break
		}

		if path.Up != nil {
			selSegs[path.Up] = struct{}{}
		}
		if path.Core != nil {
			selSegs[path.Core] = struct{}{}
		}
		if path.Down != nil {
			selSegs[path.Down] = struct{}{}
		}
	}

	selSegFunc := func(s *seg.PathSegment) bool {
		_, selected := selSegs[s]
		return selected
	}
	if upSegs != nil {
		upSegs.FilterSegs(selSegFunc)
	}
	if coreSegs != nil {
		coreSegs.FilterSegs(selSegFunc)
	}
	if downSegs != nil {
		downSegs.FilterSegs(selSegFunc)
	}
}

func matchReqIA(addr, req addr.IA) bool {
	return addr.Eq(req) || (addr.I == req.I && req.A == 0)
}

// Helper for selectConnectedSegs.
// Create all connected combinations of up-core-down segments, starting at srcIA, ending at dstIA.
// Both upSegs and downSegs may be nil. Assumes that:
// - if upSegs is present, upSegs start (==LastIA()) is srcIA,
// - if downSegs is present, downSegs end (==LastIA()) in dstIA
// - if upSegs are present, srcIA is not core
// - if downSegs are present, dstIA is not core
func allConnectedSegs(upSegs, coreSegs, downSegs *seg.Segments, srcIA, dstIA addr.IA) []connectedSegs {

	log.Trace("allConnectedSegs:")
	paths := make([]connectedSegs, 0)

	// Core direct
	for _, coreSeg := range *coreSegs {
		if matchReqIA(coreSeg.LastIA(), srcIA) && matchReqIA(coreSeg.FirstIA(), dstIA) {
			paths = append(paths, connectedSegs{
				Up:   nil,
				Core: coreSeg,
				Down: nil,
			})
		}
	}
	if upSegs != nil && downSegs != nil {
		// Up-Down direct
		for _, upSeg := range *upSegs {
			for _, downSeg := range *downSegs {
				if upSeg.FirstIA().Eq(downSeg.FirstIA()) {
					paths = append(paths, connectedSegs{
						Up:   upSeg,
						Core: nil,
						Down: downSeg,
					})
				}
			}
		}
		// Up-Core-Down
		for _, upSeg := range *upSegs {
			for _, coreSeg := range *coreSegs {
				if !upSeg.FirstIA().Eq(coreSeg.LastIA()) {
					continue
				}
				for _, downSeg := range *downSegs {
					if !coreSeg.FirstIA().Eq(downSeg.FirstIA()) {
						continue
					}
					paths = append(paths, connectedSegs{
						Up:   upSeg,
						Core: coreSeg,
						Down: downSeg,
					})
				}
			}
		}
	} else if upSegs == nil {
		// Down from src
		for _, downSeg := range *downSegs {
			log.Trace("down from src", "downFirst", downSeg.FirstIA(), "downLast", downSeg.LastIA(), "src", srcIA, "dst", dstIA)
			if matchReqIA(downSeg.FirstIA(), srcIA) {
				paths = append(paths, connectedSegs{
					Up:   nil,
					Core: nil,
					Down: downSeg,
				})
			}
		}
		// Core-Down
		for _, coreSeg := range *coreSegs {
			for _, downSeg := range *downSegs {
				log.Trace("core-down", "coreFirst", coreSeg.FirstIA(), "coreLast", coreSeg.LastIA(), "downFirst", downSeg.FirstIA(), "downLast", downSeg.LastIA(), "src", srcIA, "dst", dstIA)
				if !coreSeg.LastIA().Eq(downSeg.FirstIA()) {
					continue
				}
				paths = append(paths, connectedSegs{
					Up:   nil,
					Core: coreSeg,
					Down: downSeg,
				})
			}
		}
	} else if downSegs == nil {
		// Up to dst
		for _, upSeg := range *upSegs {
			log.Trace("up to dst", "upFirst", upSeg.FirstIA(), "upLast", upSeg.LastIA(), "src", srcIA, "dst", dstIA)
			if matchReqIA(upSeg.FirstIA(), dstIA) {
				paths = append(paths, connectedSegs{
					Up:   upSeg,
					Core: nil,
					Down: nil,
				})
			}
		}
		// Up-Core
		for _, upSeg := range *upSegs {
			for _, coreSeg := range *coreSegs {
				log.Trace("up-core:", "upFirst", upSeg.FirstIA(), "upLast", upSeg.LastIA(), "coreFirst", coreSeg.FirstIA(), "coreLast", coreSeg.LastIA(), "src", srcIA, "dst", dstIA)
				if !upSeg.FirstIA().Eq(coreSeg.LastIA()) {
					continue
				}
				paths = append(paths, connectedSegs{
					Up:   upSeg,
					Core: coreSeg,
					Down: nil,
				})
			}
		}
	}
	return paths
}
