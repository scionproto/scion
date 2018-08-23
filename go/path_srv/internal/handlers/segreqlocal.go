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
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/proto"
)

// requestID is used to generate unique request IDs for the messenger.
var requestID messenger.Counter

type segReqLocalHandler struct {
	segReqHandler
}

func NewSegReqLocalHandler(args *HandlerArgs) infra.Handler {
	f := func(r *infra.Request) {
		handler := &segReqLocalHandler{
			segReqHandler: segReqHandler{
				baseHandler: newBaseHandler(r, args),
				localIA:     args.Topology.ISD_AS,
			},
		}
		handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *segReqLocalHandler) Handle() {
	// DD 1
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
	h.srcTRC, err = h.trustStore.GetTRC(subCtx, h.localIA.I, 0)
	if err != nil {
		h.logger.Error("[segReqHandler] Failed to get TRC for src", "err", err)
		h.sendEmptySegReply(subCtx, segReq, msger)
		return
	}
	h.dstLocal = segReq.DstIA().I == h.localIA.I
	h.dstCore, err = h.isCoreDst(subCtx, msger, segReq)
	if err != nil {
		h.logger.Error("[segReqHandler] Failed to determine dest type", "err", err)
		h.sendEmptySegReply(subCtx, segReq, msger)
		return
	}
	// DD 5
	if h.dstCore {
		h.handleCoreDst(subCtx, segReq, msger, segReq.DstIA())
	} else {
		h.handleNonCoreDst(subCtx, segReq, msger, segReq.DstIA())
	}
}

func (h *segReqLocalHandler) validSrcDst(segReq *path_mgmt.SegReq) bool {
	if !segReq.SrcIA().IsZero() && !segReq.SrcIA().Eq(h.localIA) {
		h.logger.Warn("[segReqHandler] Drop, invalid srcIA",
			"srcIA", segReq.SrcIA())
		return false
	}
	return h.isValidDst(segReq)
}

// DD 5.1.1
func (h *segReqLocalHandler) handleCoreDst(ctx context.Context, segReq *path_mgmt.SegReq,
	msger infra.Messenger, dst addr.IA) {

	h.logger.Debug("[segReqHandler] handleCoreDst", "remote", !h.dstLocal)
	upSegs, err := h.fetchUpSegsFromDB(ctx)
	if err != nil {
		h.logger.Error("[segReqHandler] Failed to find up segments", "err", err)
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	if len(upSegs) == 0 {
		// TODO(lukedirtwalker): We should hold the request until the timeout of the context,
		// and continue processing as soon as we have up segments.
		h.logger.Warn("[segReqHandler] No up segments found")
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	// TODO(lukedirtwalker): in case of CacheOnly we can use a single query,
	// else we should start go routines for the core segs here.
	var coreSegs []*seg.PathSegment
	for _, src := range firstIAs(upSegs) {
		if !src.Eq(dst) {
			res, err := h.fetchCoreSegs(ctx, msger, src, dst, segReq.Flags.CacheOnly)
			if err != nil {
				h.logger.Error("[segReqHandler] Failed to find core segs", "err", err)
				continue
			}
			coreSegs = append(coreSegs, res...)
		}
	}
	h.logger.Debug("[segReqHandler] found", "up", len(upSegs), "core", len(coreSegs))
	h.sendReply(ctx, msger, upSegs, coreSegs, nil, segReq)
}

func (h *segReqLocalHandler) handleNonCoreDst(ctx context.Context, segReq *path_mgmt.SegReq,
	msger infra.Messenger, dstIA addr.IA) {

	cPS, err := h.corePSAddr(ctx, addr.IA{})
	if err != nil {
		h.logger.Error("Could not find corePS to ask for down segs", "err", err)
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	downSegs, err := h.fetchDownSegs(ctx, msger, dstIA, cPS, segReq.Flags.CacheOnly)
	if err != nil {
		h.logger.Error("Failed to find down segs", "err", err)
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	upSegs, err := h.fetchUpSegsFromDB(ctx)
	if err != nil {
		h.logger.Error("Failed to find up segs", "err", err)
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	if len(downSegs) == 0 {
		// TODO(lukedirtwalker): We should hold the request until the timeout of the context,
		// and continue processing as soon as we have down segments.
		h.logger.Warn("[segReqHandler] No down segments found")
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	var coreSegs []*seg.PathSegment
	// TODO(lukedirtwalker): in case of CacheOnly we can use a single query,
	// else we should start go routines for the core segs here.
	for _, dst := range firstIAs(downSegs) {
		for _, src := range firstIAs(upSegs) {
			if src.Eq(dst) {
				continue
			}
			cs, err := h.fetchCoreSegs(ctx, msger, src, dst, segReq.Flags.CacheOnly)
			if err != nil {
				h.logger.Error("Failed to find core segs", "src", src, "dst", dst, "err", err)
				continue
			}
			coreSegs = append(coreSegs, cs...)
		}
	}
	h.logger.Debug("[segReqHandler:handleNonCoreDst] found segs",
		"up", len(upSegs), "core", len(coreSegs), "down", len(downSegs))
	h.sendReply(ctx, msger, upSegs, coreSegs, downSegs, segReq)
}

func (h *segReqLocalHandler) fetchUpSegsFromDB(ctx context.Context) ([]*seg.PathSegment, error) {
	cASes := h.srcTRC.CoreASes.ASList()
	return h.fetchSegsFromDB(ctx, &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_up},
		StartsAt: cASes,
		EndsAt:   []addr.IA{h.localIA},
	})
}

func (h *segReqLocalHandler) fetchCoreSegs(ctx context.Context,
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
	cPS, err := h.corePSAddr(ctx, src)
	if err != nil {
		return nil, err
	}
	_, err = h.fetchAndSaveSegs(ctx, msger, src, dst, cPS, requestID.Next())
	if err != nil {
		return nil, err
	}
	// TODO(lukedirtwalker): if fetchAndSaveSegs returns verified segs we don't need to query.
	return h.fetchSegsFromDB(ctx, q)
}

func (h *segReqLocalHandler) corePSAddr(ctx context.Context, core addr.IA) (net.Addr, error) {
	upSegs, err := h.fetchUpSegsFromDB(ctx)
	if err != nil {
		return nil, err
	}
	if !core.IsZero() {
		upSegs = filterSegs(upSegs, func(s *seg.PathSegment) bool {
			return s.FirstIA().Eq(core)
		})
	}
	if len(upSegs) < 1 {
		// TODO(lukedirtwalker): We should hold the request until the timeout of the context,
		// and continue processing as soon as we have up segments.
		return nil, common.NewBasicError("No up segments found!", nil)
	}
	// select random reachable core AS.
	dstIA := upSegs[rand.Intn(len(upSegs))].FirstIA()
	paths := combinator.Combine(h.localIA, dstIA, upSegs, nil, nil)
	if len(paths) < 1 {
		return nil, common.NewBasicError("No path to local cPS", nil)
	}
	return h.addrFromPath(paths[0], dstIA)
}
