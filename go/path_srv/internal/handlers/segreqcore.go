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
	"github.com/scionproto/scion/go/lib/infra/dedupe"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/path_srv/internal/addrutil"
	"github.com/scionproto/scion/go/proto"
)

type segReqCoreHandler struct {
	segReqHandler
}

func NewSegReqCoreHandler(args HandlerArgs, segsDeduper dedupe.Deduper) infra.Handler {
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &segReqCoreHandler{
			segReqHandler: segReqHandler{
				baseHandler: newBaseHandler(r, args),
				localIA:     args.IA,
				segsDeduper: segsDeduper,
			},
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *segReqCoreHandler) Handle() *infra.HandlerResult {
	logger := log.FromCtx(h.request.Context())
	segReq, ok := h.request.Message.(*path_mgmt.SegReq)
	if !ok {
		logger.Error("[segReqCoreHandler] wrong message type, expected path_mgmt.SegReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return infra.MetricsErrInternal
	}
	logger.Debug("[segReqCoreHandler] Received", "segReq", segReq)
	rw, ok := infra.ResponseWriterFromContext(h.request.Context())
	if !ok {
		logger.Warn("[segReqHandler] Unable to reply to client, no response writer found")
		return infra.MetricsErrInternal
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	if !h.isValidDst(segReq) {
		rw.SendSegReply(subCtx, &path_mgmt.SegReply{Req: segReq})
		return infra.MetricsErrInvalid
	}
	h.handleReq(subCtx, rw, segReq)
	// TODO(lukedirtwalker): Handle errors
	return infra.MetricsResultOk
}

func (h *segReqCoreHandler) handleReq(ctx context.Context, rw infra.ResponseWriter,
	segReq *path_mgmt.SegReq) {

	logger := log.FromCtx(ctx)
	dstISDLocal := segReq.DstIA().I == h.localIA.I
	if dstISDLocal && segReq.DstIA().A == 0 {
		rw.SendSegReply(ctx, &path_mgmt.SegReply{Req: segReq})
		return
	}
	dstCore, err := h.isCoreDst(ctx, segReq)
	if err != nil {
		logger.Error("[segReqCoreHandler] Failed to determine dest type", "err", err)
		rw.SendSegReply(ctx, &path_mgmt.SegReply{Req: segReq})
		return
	}
	if dstCore {
		h.handleCoreDst(ctx, rw, segReq)
		return
	}
	var downSegs seg.Segments
	if dstISDLocal || segReq.Flags.CacheOnly {
		downSegs, err = h.fetchDownSegsFromDB(ctx, segReq.DstIA())
	} else {
		downSegs, err = h.fetchDownSegsFromRemoteCore(ctx, segReq.DstIA())
	}
	if err != nil {
		logger.Error("Failed to fetch down segments", "err", err)
		rw.SendSegReply(ctx, &path_mgmt.SegReply{Req: segReq})
		return
	}
	if len(downSegs) == 0 {
		logger.Debug("[segReqCoreHandler] no down segs found")
		rw.SendSegReply(ctx, &path_mgmt.SegReply{Req: segReq})
		return
	}
	var coreSegs []*seg.PathSegment
	// if request came from same AS also return core segs, to start of down segs.
	if segReq.SrcIA().Equal(h.localIA) {
		ias := downSegs.FirstIAs()
		downIAs := ias[:0]
		for _, ia := range ias {
			if !ia.Equal(h.localIA) {
				downIAs = append(downIAs, ia)
			}
		}
		if len(downIAs) > 0 {
			// If we have direct down segments (len(ias) != len(downIAs)) we don't need to retry,
			// otherwise only if !CacheOnly.
			retry := len(ias) == len(downIAs) && !segReq.Flags.CacheOnly
			coreSegs, err = h.fetchCoreSegsFromDB(ctx, downIAs, retry)
			if err != nil {
				logger.Error("[segReqCoreHandler] Failed to find core segs", "err", err)
				rw.SendSegReply(ctx, &path_mgmt.SegReply{Req: segReq})
				return
			}
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
	logger.Debug("[segReqCoreHandler] found segs", "core", len(coreSegs), "down", len(downSegs))
	h.sendReply(ctx, rw, nil, coreSegs, downSegs, segReq)
}

func (h *segReqCoreHandler) handleCoreDst(ctx context.Context, rw infra.ResponseWriter,
	segReq *path_mgmt.SegReq) {

	logger := log.FromCtx(ctx)
	coreSegs, err := h.fetchCoreSegsFromDB(ctx, []addr.IA{segReq.DstIA()}, !segReq.Flags.CacheOnly)
	if err != nil {
		logger.Error("Failed to find core segs", "err", err)
		return
	}
	logger.Debug("[segReqHandler:handleCoreDst] found segs", "core", len(coreSegs))
	h.sendReply(ctx, rw, nil, coreSegs, nil, segReq)
}

func (h *segReqCoreHandler) fetchCoreSegsFromDB(ctx context.Context,
	dstIAs []addr.IA, retry bool) ([]*seg.PathSegment, error) {

	q := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_core},
		StartsAt: dstIAs,
		EndsAt:   []addr.IA{h.localIA},
	}
	if retry {
		return h.fetchSegsFromDBRetry(ctx, q)
	}
	return h.fetchSegsFromDB(ctx, q)
}

func (h *segReqCoreHandler) fetchDownSegsFromDB(ctx context.Context,
	dstIA addr.IA) ([]*seg.PathSegment, error) {

	q := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_down},
		EndsAt:   []addr.IA{dstIA},
	}
	return h.fetchSegsFromDB(ctx, q)
}

func (h *segReqCoreHandler) fetchDownSegsFromRemoteCore(ctx context.Context,
	dstIA addr.IA) ([]*seg.PathSegment, error) {

	cPSResolve := func() (net.Addr, error) {
		return h.corePSAddr(ctx, dstIA.I)
	}
	downSegs, err := h.fetchDownSegs(ctx, dstIA, cPSResolve, false)
	if err != nil {
		return nil, err
	}
	return downSegs, nil
}

func (h *segReqCoreHandler) corePSAddr(ctx context.Context, destISD addr.ISD) (net.Addr, error) {
	coreSegs, err := h.fetchCoreSegsFromDB(ctx, []addr.IA{{I: destISD}}, true)
	if err != nil {
		return nil, err
	}
	if len(coreSegs) < 1 {
		return nil, common.NewBasicError("No core segments found!", nil)
	}
	// select random reachable core AS.
	seg := coreSegs[rand.Intn(len(coreSegs))]
	return addrutil.GetPath(addr.SvcPS, seg, seg.FirstIA(), h.topology)
}
