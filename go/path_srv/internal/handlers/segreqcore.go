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
	"math/rand"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/proto"
)

type segReqCoreHandler struct {
	segReqHandler
}

func NewSegReqCoreHandler(args HandlerArgs) infra.Handler {
	f := func(r *infra.Request) {
		handler := &segReqCoreHandler{
			segReqHandler: segReqHandler{
				baseHandler: newBaseHandler(r, args),
				localIA:     args.Topology.ISD_AS,
			},
		}
		handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *segReqCoreHandler) Handle() {
	segReq, ok := h.request.Message.(*path_mgmt.SegReq)
	if !ok {
		h.logger.Error("[segReqCoreHandler] wrong message type, expected path_mgmt.SegReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	h.logger.Debug("[segReqCoreHandler] Received", "segReq", segReq)
	msger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		h.logger.Warn("[segReqCoreHandler] Unable to service request, no Messenger found")
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	if !h.isValidDst(segReq) {
		h.sendEmptySegReply(subCtx, segReq, msger)
		return
	}
	h.handleReq(subCtx, msger, segReq)
}

func (h *segReqCoreHandler) handleReq(ctx context.Context,
	msger infra.Messenger, segReq *path_mgmt.SegReq) {

	dstISDLocal := segReq.DstIA().I == h.localIA.I
	if dstISDLocal && segReq.DstIA().A == 0 {
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	dstCore, err := h.isCoreDst(ctx, msger, segReq)
	if err != nil {
		h.logger.Error("[segReqHandler] Failed to determine dest type", "err", err)
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	if dstCore {
		h.handleCoreDst(ctx, msger, segReq)
		return
	}
	var downSegs seg.Segments
	if dstISDLocal || segReq.Flags.CacheOnly {
		downSegs, err = h.fetchDownSegsFromDB(ctx, segReq.DstIA())
	} else {
		downSegs, err = h.fetchDownSegsFromRemoteCore(ctx, msger, segReq.DstIA())
	}
	if err != nil {
		h.logger.Error("Failed to fetch down segments", "err", err)
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	var coreSegs []*seg.PathSegment
	// if request came from same AS also return core segs, to start of down segs.
	if segReq.SrcIA().Eq(h.localIA) {
		coreSegs, err = h.fetchCoreSegsFromDB(ctx, downSegs.FirstIAs())
		if err != nil {
			h.logger.Error("[segReqHandler] Failed to find core segs", "err", err)
			h.sendEmptySegReply(ctx, segReq, msger)
			return
		}
		// Remove disconnected down segs.
		// Core segments can only end at the given down segs, thus do not need to be filtered.
		coreDowns := segsToMap(coreSegs, (*seg.PathSegment).FirstIA)
		// localIA is always a valid start point
		coreDowns[h.localIA] = struct{}{}
		downSegs.FilterSegs(func(s *seg.PathSegment) bool {
			_, coreExists := coreDowns[s.FirstIA()]
			return coreExists
		})
	}
	h.logger.Debug("[segReqHandler] found segs", "core", len(coreSegs), "down", len(downSegs))
	h.sendReply(ctx, msger, nil, coreSegs, downSegs, segReq)
}

func (h *segReqCoreHandler) handleCoreDst(ctx context.Context,
	msger infra.Messenger, segReq *path_mgmt.SegReq) {

	coreSegs, err := h.fetchCoreSegsFromDB(ctx, []addr.IA{segReq.DstIA()})
	if err != nil {
		h.logger.Error("Failed to find core segs", "err", err)
		return
	}
	h.logger.Debug("[segReqHandler:handleCoreDst] found segs", "core", len(coreSegs))
	h.sendReply(ctx, msger, nil, coreSegs, nil, segReq)
}

func (h *segReqCoreHandler) fetchCoreSegsFromDB(ctx context.Context,
	dstIAs []addr.IA) ([]*seg.PathSegment, error) {

	return h.fetchSegsFromDB(ctx, &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_core},
		StartsAt: dstIAs,
		EndsAt:   []addr.IA{h.localIA},
	})
}

func (h *segReqCoreHandler) fetchDownSegsFromDB(ctx context.Context,
	dstIA addr.IA) ([]*seg.PathSegment, error) {

	q := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_down},
		EndsAt:   []addr.IA{dstIA},
	}
	return h.fetchSegsFromDB(ctx, q)
}

func (h *segReqCoreHandler) fetchDownSegsFromRemoteCore(ctx context.Context, msger infra.Messenger,
	dstIA addr.IA) ([]*seg.PathSegment, error) {

	// down segs
	cPS, err := h.corePSAddr(ctx, dstIA.I)
	if err != nil {
		return nil, err
	}
	downSegs, err := h.fetchDownSegs(ctx, msger, dstIA, cPS, false)
	if err != nil {
		return nil, err
	}
	return downSegs, nil
}

func (h *segReqCoreHandler) corePSAddr(ctx context.Context, destISD addr.ISD) (net.Addr, error) {
	coreSegs, err := h.fetchCoreSegsFromDB(ctx, []addr.IA{{I: destISD}})
	if err != nil {
		return nil, err
	}
	if len(coreSegs) < 1 {
		return nil, common.NewBasicError("No core segments found!", nil)
	}
	// select random reachable core AS.
	seg := coreSegs[rand.Intn(len(coreSegs))]
	return h.psAddrFromSeg(seg, seg.FirstIA())
}
