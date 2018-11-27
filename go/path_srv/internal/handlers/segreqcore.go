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
	"github.com/scionproto/scion/go/path_srv/internal/metrics"
	"github.com/scionproto/scion/go/proto"
)

type segReqCoreHandler struct {
	segReqHandler
}

func NewSegReqCoreHandler(args HandlerArgs, segsDeduper dedupe.Deduper) infra.Handler {
	f := func(r *infra.Request) {
		handler := &segReqCoreHandler{
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

func (h *segReqCoreHandler) Handle() metrics.Status {
	logger := log.FromCtx(h.request.Context())
	segReq, ok := h.request.Message.(*path_mgmt.SegReq)
	if !ok {
		logger.Error("[segReqCoreHandler] wrong message type, expected path_mgmt.SegReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		metrics.ErrInc(metrics.SegReq, metrics.ReqProgErr, 0)
		return metrics.Err
	}
	logger.Debug("[segReqCoreHandler] Received", "segReq", segReq)
	msger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		logger.Warn("[segReqCoreHandler] Unable to service request, no Messenger found")
		metrics.ErrInc(metrics.SegReq, metrics.ReqProgErr, 0)
		return metrics.Err
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	if !h.isValidDst(segReq) {
		metrics.ErrInc(metrics.SegReq, metrics.ReqProgErr, segReq.DstIA().I)
		return metrics.ErrInvalid
	}
	dstISDLocal := segReq.DstIA().I == h.localIA.I
	if dstISDLocal && segReq.DstIA().A == 0 {
		metrics.ErrInc(metrics.SegReq, metrics.ReqInvalid, segReq.DstIA().I)
		logger.Warn("[segReqCoreHandler] Invalid dst (local AS 0)", "dst", segReq.DstIA())
		h.sendEmptySegReply(subCtx, segReq, msger)
		return metrics.ErrInvalid
	}
	if err := h.handle(subCtx, segReq, msger); err != nil {
		logger.Error("[segReqCoreHandler] Failed to process request", "err", err)
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

func (h *segReqCoreHandler) handle(ctx context.Context,
	segReq *path_mgmt.SegReq, msger infra.Messenger) error {

	logger := log.FromCtx(ctx)
	dstISDLocal := segReq.DstIA().I == h.localIA.I
	dstCore, err := h.isCoreDst(ctx, msger, segReq)
	if err != nil {
		metrics.ErrInc(metrics.SegReq, metrics.ReqTrustErr, segReq.DstIA().I)
		return common.NewBasicError("Failed to determine dest type", err)
	}
	if dstCore {
		return h.handleCoreDst(ctx, msger, segReq)
	}
	var downSegs seg.Segments
	if dstISDLocal || segReq.Flags.CacheOnly {
		downSegs, err = h.fetchDownSegsFromDB(ctx, segReq.DstIA())
	} else {
		downSegs, err = h.fetchDownSegsFromRemoteCore(ctx, msger, segReq.DstIA())
	}
	if err != nil {
		return common.NewBasicError("Failed to fetch down segments", err)
	}
	if len(downSegs) == 0 {
		return common.NewBasicError("No down segs found", nil)
	}
	var coreSegs []*seg.PathSegment
	// if request came from same AS also return core segs, to start of down segs.
	if segReq.SrcIA().Eq(h.localIA) {
		ias := downSegs.FirstIAs()
		downIAs := ias[:0]
		for _, ia := range ias {
			if !ia.Eq(h.localIA) {
				downIAs = append(downIAs, ia)
			}
		}
		if len(downIAs) > 0 {
			// If we have direct down segments (len(ias) != len(downIAs)) we don't need to retry,
			// otherwise only if !CacheOnly.
			retry := len(ias) == len(downIAs) && !segReq.Flags.CacheOnly
			coreSegs, err = h.fetchCoreSegsFromDB(ctx, downIAs, retry)
			if err != nil {
				return common.NewBasicError("Failed to find core segs", err)
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
	h.sendReply(ctx, msger, nil, coreSegs, downSegs, segReq)
	return nil
}

func (h *segReqCoreHandler) handleCoreDst(ctx context.Context,
	msger infra.Messenger, segReq *path_mgmt.SegReq) error {

	logger := log.FromCtx(ctx)
	coreSegs, err := h.fetchCoreSegsFromDB(ctx, []addr.IA{segReq.DstIA()}, !segReq.Flags.CacheOnly)
	if err != nil {
		return common.NewBasicError("Failed to find core segs", err)
	}
	logger.Debug("[segReqHandler:handleCoreDst] found segs", "core", len(coreSegs))
	h.sendReply(ctx, msger, nil, coreSegs, nil, segReq)
	return nil
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

func (h *segReqCoreHandler) fetchDownSegsFromRemoteCore(ctx context.Context, msger infra.Messenger,
	dstIA addr.IA) ([]*seg.PathSegment, error) {

	cPSResolve := func() (net.Addr, error) {
		return h.corePSAddr(ctx, dstIA.I)
	}
	downSegs, err := h.fetchDownSegs(ctx, msger, dstIA, cPSResolve, false)
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
