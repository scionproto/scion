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
	"math/rand"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/dedupe"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/path_srv/internal/addrutil"
	"github.com/scionproto/scion/go/path_srv/internal/metrics"
	"github.com/scionproto/scion/go/proto"
)

type segReqNonCoreHandler struct {
	segReqHandler
}

func NewSegReqNonCoreHandler(args HandlerArgs, segsDeduper dedupe.Deduper) infra.Handler {
	f := func(r *infra.Request) {
		handler := &segReqNonCoreHandler{
			segReqHandler: segReqHandler{
				baseHandler: newBaseHandler(r, args),
				localIA:     args.IA,
				segsDeduper: segsDeduper,
			},
		}
		metrics.RunHandle(metrics.SegReq, handler.Handle)
	}
	return infra.HandlerFunc(f)
}

func (h *segReqNonCoreHandler) Handle() metrics.Status {
	logger := log.FromCtx(h.request.Context())
	segReq, ok := h.request.Message.(*path_mgmt.SegReq)
	if !ok {
		logger.Error("[segReqHandler] wrong message type, expected path_mgmt.SegReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return metrics.Err
	}
	logger.Debug("[segReqHandler] Received", "segReq", segReq)
	msger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		logger.Error("[segReqHandler] Unable to service request, no Messenger found")
		return metrics.Err
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	if !h.validSrcDst(segReq) {
		return metrics.ErrInvalid
	}
	if err := h.handle(subCtx, segReq, msger); err != nil {
		logger.Error("[segReqHandler] Failed to process request", "err", err)
		h.sendEmptySegReply(subCtx, segReq, msger)
		if common.IsTimeoutErr(err) {
			return metrics.ErrTimeout
		}
		return metrics.Err
	}
	if segReq.Flags.CacheOnly {
		return metrics.OkCached
	}
	// TODO(lukedirtwalker): Find out whether we hit the cache or not.
	return metrics.Ok
}

func (h *segReqNonCoreHandler) validSrcDst(segReq *path_mgmt.SegReq) bool {
	logger := log.FromCtx(h.request.Context())
	if !segReq.SrcIA().IsZero() && !segReq.SrcIA().Eq(h.localIA) {
		logger.Warn("[segReqHandler] Drop, invalid srcIA",
			"srcIA", segReq.SrcIA())
		return false
	}
	return h.isValidDst(segReq)
}

func (h *segReqNonCoreHandler) handle(ctx context.Context,
	segReq *path_mgmt.SegReq, msger infra.Messenger) error {

	var err error
	dstCore, err := h.isCoreDst(ctx, msger, segReq)
	if err != nil {
		return common.NewBasicError("Failed to determine dest type", err)
	}
	coreASes, err := h.coreASes(ctx)
	if err != nil {
		return common.NewBasicError("Failed to find local core ASes", err)
	}
	if dstCore {
		return h.handleCoreDst(ctx, segReq, msger, segReq.DstIA(), coreASes.ASList())
	}
	return h.handleNonCoreDst(ctx, segReq, msger, segReq.DstIA(), coreASes.ASList())
}

func (h *segReqNonCoreHandler) handleCoreDst(ctx context.Context, segReq *path_mgmt.SegReq,
	msger infra.Messenger, dst addr.IA, coreASes []addr.IA) error {

	logger := log.FromCtx(ctx)
	dstISDLocal := segReq.DstIA().I == h.localIA.I
	logger.Debug("[segReqHandler] handleCoreDst", "remote", dstISDLocal)
	upSegs, err := h.fetchUpSegsFromDB(ctx, coreASes, !segReq.Flags.CacheOnly)
	if err != nil {
		return common.NewBasicError("Failed to find up segments", err)
	}
	if len(upSegs) == 0 {
		return common.NewBasicError("No up segments found", nil)
	}
	// TODO(lukedirtwalker): in case of CacheOnly we can use a single query,
	// else we should start go routines for the core segs here.
	var coreSegs []*seg.PathSegment
	// All firstIAs of upSegs that are connected, used for filtering later.
	connFirstIAs := make(map[addr.IA]struct{})
	// TODO(lukedirtwalker): we shouldn't just query all cores, this could be a lot of overhead.
	// Add a limit of cores we query.
	for _, src := range upSegs.FirstIAs() {
		if !src.Eq(dst) {
			res, err := h.fetchCoreSegs(ctx, msger, src, dst, segReq.Flags.CacheOnly)
			if err != nil {
				logger.Error("[segReqHandler] Failed to find core segs", "err", err)
				continue
			}
			if len(res) > 0 {
				coreSegs = append(coreSegs, res...)
				connFirstIAs[src] = struct{}{}
			}
		} else {
			connFirstIAs[src] = struct{}{}
		}
	}
	// Make sure we only return connected segments.
	upSegs.FilterSegs(func(s *seg.PathSegment) bool {
		_, connected := connFirstIAs[s.FirstIA()]
		return connected
	})
	logger.Debug("[segReqHandler] found", "up", len(upSegs), "core", len(coreSegs))
	h.sendReply(ctx, msger, upSegs, coreSegs, nil, segReq)
	return nil
}

func (h *segReqNonCoreHandler) handleNonCoreDst(ctx context.Context, segReq *path_mgmt.SegReq,
	msger infra.Messenger, dstIA addr.IA, coreASes []addr.IA) error {

	logger := log.FromCtx(ctx)
	cPSResolve := func() (net.Addr, error) {
		return h.corePSAddr(ctx, coreASes)
	}
	downSegs, err := h.fetchDownSegs(ctx, msger, dstIA, cPSResolve, segReq.Flags.CacheOnly)
	if err != nil {
		return common.NewBasicError("Failed to find down segs", err)
	}
	if len(downSegs) == 0 {
		return common.NewBasicError("No down segments found", nil)
	}
	upSegs, err := h.fetchUpSegsFromDB(ctx, coreASes, !segReq.Flags.CacheOnly)
	if err != nil {
		return common.NewBasicError("Failed to find up segs", err)
	}
	var coreSegs []*seg.PathSegment
	// All firstIAs of up-/down-Segs that are connected, used for filtering later.
	connUpFirstIAs := make(map[addr.IA]struct{})
	connDownFirstIAs := make(map[addr.IA]struct{})
	// TODO(lukedirtwalker): in case of CacheOnly we can use a single query,
	// else we should start go routines for the core segs here.
	for _, dst := range downSegs.FirstIAs() {
		// TODO(lukedirtwalker): we shouldn't just query all cores, this could be a lot of overhead.
		// Add a limit of cores we query.
		for _, src := range upSegs.FirstIAs() {
			if src.Eq(dst) {
				connUpFirstIAs[src] = struct{}{}
				connDownFirstIAs[dst] = struct{}{}
				continue
			}
			cs, err := h.fetchCoreSegs(ctx, msger, src, dst, segReq.Flags.CacheOnly)
			if err != nil {
				logger.Error("Failed to find core segs", "src", src, "dst", dst, "err", err)
				continue
			}
			if len(cs) > 0 {
				coreSegs = append(coreSegs, cs...)
				connUpFirstIAs[src] = struct{}{}
				connDownFirstIAs[dst] = struct{}{}
			}
		}
	}
	// Make sure we only return connected segments.
	// No need to filter cores, since we only query for connected ones.
	upSegs.FilterSegs(func(s *seg.PathSegment) bool {
		_, connected := connUpFirstIAs[s.FirstIA()]
		return connected
	})
	downSegs.FilterSegs(func(s *seg.PathSegment) bool {
		_, connected := connDownFirstIAs[s.FirstIA()]
		return connected
	})
	logger.Debug("[segReqHandler:handleNonCoreDst] found segs",
		"up", len(upSegs), "core", len(coreSegs), "down", len(downSegs))
	h.sendReply(ctx, msger, upSegs, coreSegs, downSegs, segReq)
	return nil
}

func (h *segReqNonCoreHandler) fetchUpSegsFromDB(ctx context.Context,
	coreASes []addr.IA, retry bool) (seg.Segments, error) {

	query := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_up},
		StartsAt: coreASes,
		EndsAt:   []addr.IA{h.localIA},
	}
	if retry {
		return h.fetchSegsFromDBRetry(ctx, query)
	}
	return h.fetchSegsFromDB(ctx, query)
}

func (h *segReqNonCoreHandler) fetchCoreSegs(ctx context.Context,
	msger infra.Messenger, src, dst addr.IA, dbOnly bool) ([]*seg.PathSegment, error) {

	logger := log.FromCtx(ctx)
	logger.Debug("[segReqHanlder:fetchCoreSegs]", "query", fmt.Sprintf("%v->%v", src, dst))
	// try local cache first, inverse query since core segs are stored in inverse direction.
	q := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_core},
		StartsAt: []addr.IA{dst},
		EndsAt:   []addr.IA{src},
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
				logger.Warn("[segReqHandler] failed to get last query", "err", err)
			}
		}
		if !refetch {
			return segs, nil
		}
	}
	// try remote:
	cPS, err := h.corePSAddr(ctx, []addr.IA{src})
	if err != nil {
		return nil, err
	}
	if err = h.fetchAndSaveSegs(ctx, msger, src, dst, cPS); err != nil {
		return nil, err
	}
	// TODO(lukedirtwalker): if fetchAndSaveSegs returns verified segs we don't need to query.
	return h.fetchSegsFromDB(ctx, q)
}

func (h *segReqNonCoreHandler) corePSAddr(ctx context.Context,
	coreASes []addr.IA) (net.Addr, error) {

	upSegs, err := h.fetchUpSegsFromDB(ctx, coreASes, true)
	if err != nil {
		return nil, err
	}
	if len(upSegs) < 1 {
		return nil, common.NewBasicError("No up segments found!", nil)
	}
	// select a core AS we have an up segment to.
	seg := upSegs[rand.Intn(len(upSegs))]
	return addrutil.GetPath(addr.SvcPS, seg, seg.FirstIA(), h.topology)
}
