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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/proto"
)

// requestID is used to generate unique request IDs for the messenger.
var requestID messenger.Counter

type segReqNonCoreHandler struct {
	segReqHandler
}

func NewSegReqNonCoreHandler(args HandlerArgs) infra.Handler {
	f := func(r *infra.Request) {
		handler := &segReqNonCoreHandler{
			segReqHandler: segReqHandler{
				baseHandler: newBaseHandler(r, args),
				localIA:     args.Topology.ISD_AS,
			},
		}
		handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *segReqNonCoreHandler) Handle() {
	segReq, ok := h.request.Message.(*path_mgmt.SegReq)
	if !ok {
		h.logger.Error("[segReqHandler] wrong message type, expected path_mgmt.SegReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	h.logger.Debug("[segReqHandler] Received", "segReq", segReq)
	msger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		h.logger.Warn("[segReqHandler] Unable to service request, no Messenger found")
		return
	}
	if !h.validSrcDst(segReq) {
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	var err error
	dstCore, err := h.isCoreDst(subCtx, msger, segReq)
	if err != nil {
		h.logger.Error("[segReqHandler] Failed to determine dest type", "err", err)
		h.sendEmptySegReply(subCtx, segReq, msger)
		return
	}
	coreASes, err := h.coreASes(subCtx)
	if err != nil {
		h.logger.Error("[segReqHandler] Failed to find local core ASes", "err", err)
		h.sendEmptySegReply(subCtx, segReq, msger)
		return
	}
	if dstCore {
		h.handleCoreDst(subCtx, segReq, msger, segReq.DstIA(), coreASes.ASList())
	} else {
		h.handleNonCoreDst(subCtx, segReq, msger, segReq.DstIA(), coreASes.ASList())
	}
}

func (h *segReqNonCoreHandler) validSrcDst(segReq *path_mgmt.SegReq) bool {
	if !segReq.SrcIA().IsZero() && !segReq.SrcIA().Eq(h.localIA) {
		h.logger.Warn("[segReqHandler] Drop, invalid srcIA",
			"srcIA", segReq.SrcIA())
		return false
	}
	return h.isValidDst(segReq)
}

func (h *segReqNonCoreHandler) handleCoreDst(ctx context.Context, segReq *path_mgmt.SegReq,
	msger infra.Messenger, dst addr.IA, coreASes []addr.IA) {

	dstISDLocal := segReq.DstIA().I == h.localIA.I
	h.logger.Debug("[segReqHandler] handleCoreDst", "remote", dstISDLocal)
	upSegs, err := h.fetchUpSegsFromDB(ctx, coreASes)
	if err != nil {
		h.logger.Error("[segReqHandler] Failed to find up segments", "err", err)
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	if len(upSegs) == 0 {
		// TODO(lukedirtwalker): We should hold the request until the timeout of the context,
		// and continue processing as soon as we have up segments. (only if !CacheOnly)
		h.logger.Warn("[segReqHandler] No up segments found")
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	// TODO(lukedirtwalker): in case of CacheOnly we can use a single query,
	// else we should start go routines for the core segs here.
	var coreSegs []*seg.PathSegment
	// All firstIAs of upSegs that are connected, used for filtering later.
	connFirstIAs := make(map[addr.IA]struct{})
	// TODO(lukedirtwalker): we shouldn't just query all cores, this could be a lot of overhead.
	// Add a limit of cores we query.
	for _, src := range firstIAs(upSegs) {
		if !src.Eq(dst) {
			res, err := h.fetchCoreSegs(ctx, msger, src, dst, segReq.Flags.CacheOnly)
			if err != nil {
				h.logger.Error("[segReqHandler] Failed to find core segs", "err", err)
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
	upSegs = filterSegs(upSegs, func(s *seg.PathSegment) bool {
		_, connected := connFirstIAs[s.FirstIA()]
		return connected
	})
	h.logger.Debug("[segReqHandler] found", "up", len(upSegs), "core", len(coreSegs))
	h.sendReply(ctx, msger, upSegs, coreSegs, nil, segReq)
}

func (h *segReqNonCoreHandler) handleNonCoreDst(ctx context.Context, segReq *path_mgmt.SegReq,
	msger infra.Messenger, dstIA addr.IA, coreASes []addr.IA) {

	cPS, err := h.corePSAddr(ctx, coreASes)
	if err != nil {
		h.logger.Error("failed to get path to core to query for down segs", "err", err)
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	downSegs, err := h.fetchDownSegs(ctx, msger, dstIA, cPS, segReq.Flags.CacheOnly)
	if err != nil {
		h.logger.Error("Failed to find down segs", "err", err)
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	if len(downSegs) == 0 {
		h.logger.Warn("[segReqHandler] No down segments found")
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	upSegs, err := h.fetchUpSegsFromDB(ctx, coreASes)
	if err != nil {
		h.logger.Error("Failed to find up segs", "err", err)
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	var coreSegs []*seg.PathSegment
	// All firstIAs of up-/down-Segs that are connected, used for filtering later.
	connUpFirstIAs := make(map[addr.IA]struct{})
	connDownFirstIAs := make(map[addr.IA]struct{})
	// TODO(lukedirtwalker): in case of CacheOnly we can use a single query,
	// else we should start go routines for the core segs here.
	for _, dst := range firstIAs(downSegs) {
		// TODO(lukedirtwalker): we shouldn't just query all cores, this could be a lot of overhead.
		// Add a limit of cores we query.
		for _, src := range firstIAs(upSegs) {
			if src.Eq(dst) {
				connUpFirstIAs[src] = struct{}{}
				connDownFirstIAs[dst] = struct{}{}
				continue
			}
			cs, err := h.fetchCoreSegs(ctx, msger, src, dst, segReq.Flags.CacheOnly)
			if err != nil {
				h.logger.Error("Failed to find core segs", "src", src, "dst", dst, "err", err)
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
	upSegs = filterSegs(upSegs, func(s *seg.PathSegment) bool {
		_, connected := connUpFirstIAs[s.FirstIA()]
		return connected
	})
	downSegs = filterSegs(downSegs, func(s *seg.PathSegment) bool {
		_, connected := connDownFirstIAs[s.FirstIA()]
		return connected
	})
	h.logger.Debug("[segReqHandler:handleNonCoreDst] found segs",
		"up", len(upSegs), "core", len(coreSegs), "down", len(downSegs))
	h.sendReply(ctx, msger, upSegs, coreSegs, downSegs, segReq)
}

func (h *segReqNonCoreHandler) fetchUpSegsFromDB(ctx context.Context,
	coreASes []addr.IA) ([]*seg.PathSegment, error) {
	return h.fetchSegsFromDB(ctx, &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_up},
		StartsAt: coreASes,
		EndsAt:   []addr.IA{h.localIA},
	})
}

func (h *segReqNonCoreHandler) fetchCoreSegs(ctx context.Context,
	msger infra.Messenger, src, dst addr.IA, dbOnly bool) ([]*seg.PathSegment, error) {

	h.logger.Debug("[segReqHanlder:fetchCoreSegs]", "query", fmt.Sprintf("%v->%v", src, dst))
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
	// TODO(lukedirtwalker): also query core if we haven't for a long time.
	if dbOnly || len(segs) > 0 {
		return segs, nil
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

	upSegs, err := h.fetchUpSegsFromDB(ctx, coreASes)
	if err != nil {
		return nil, err
	}
	if len(upSegs) < 1 {
		// TODO(lukedirtwalker): We should hold the request until the timeout of the context,
		// and continue processing as soon as we have up segments. (only if !CacheOnly)
		return nil, common.NewBasicError("No up segments found!", nil)
	}
	// select a core AS we have an up segment to.
	seg := upSegs[rand.Intn(len(upSegs))]
	return h.psAddrFromSeg(seg, seg.FirstIA())
}
