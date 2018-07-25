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
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/pathdb/conn"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

type segReqCoreHandler struct {
	segReqHandler
}

func NewSegReqCoreHandler(pathDB conn.Conn, revCache revcache.RevCache,
	topology *topology.Topo, trustStore *trust.Store) infra.Handler {

	f := func(r *infra.Request) {
		handler := &segReqCoreHandler{
			segReqHandler: segReqHandler{
				baseHandler: baseHandler{
					request:    r,
					pathDB:     pathDB,
					revCache:   revCache,
					trustStore: trustStore,
					topology:   topology,
					logger:     r.Logger,
				},
				localIA: topology.ISD_AS,
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
	if !h.validDst(segReq) {
		return
	}
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	var err error
	h.srcTRC, err = h.trustStore.GetTRC(subCtx, h.localIA.I, trust.LatestVersion)
	if err != nil {
		h.logger.Error("[segReqHandler] Failed to get TRC for src", "err", err)
		h.sendEmptySegReply(subCtx, segReq, msger)
		return
	}
	h.dstLocal = segReq.DstIA().I == h.localIA.I
	h.dstCore, err = h.isCoreDst(subCtx, msger, segReq)
	if err != nil {
		h.logger.Error("[segReqHandler] Failed to determine dest type", "err", err)
		return
	}
	h.handleReq(subCtx, msger, segReq)
}

func (h *segReqCoreHandler) handleReq(ctx context.Context,
	msger infra.Messenger, segReq *path_mgmt.SegReq) {

	if h.dstLocal && segReq.DstIA().A == 0 {
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	if h.dstCore {
		h.handleCoreDst(ctx, msger, segReq)
		return
	}
	// down segs
	downSegs, err := h.downSegs(ctx, msger, segReq.DstIA(), h.dstLocal || segReq.Flags.CacheOnly)
	if err != nil {
		h.logger.Error("[segReqHandler] Failed to find down segs", "err", err)
		return
	}
	var coreSegs []*seg.PathSegment
	// if request came from same AS also return core segs, to start of down segs.
	if segReq.SrcIA().Eq(h.localIA) {
		// TODO handle downSegs empty case!!!
		coreSegs, err = h.coreSegs(ctx, firstIAs(downSegs))
		if err != nil {
			h.logger.Error("[segReqHandler] Failed to find core segs", "err", err)
			return
		}
	}
	h.logger.Debug("[segReqHandler] found segs", "core", len(coreSegs), "down", len(downSegs))
	h.sendReply(ctx, msger, nil, coreSegs, downSegs, segReq)
}

func (h *segReqCoreHandler) handleCoreDst(ctx context.Context,
	msger infra.Messenger, segReq *path_mgmt.SegReq) {

	coreSegs, err := h.coreSegs(ctx, []addr.IA{segReq.DstIA()})
	if err != nil {
		h.logger.Error("Failed to find core segs", "err", err)
		return
	}
	h.logger.Debug("[segReqHandler:handleCoreDst] found segs", "core", len(coreSegs))
	h.sendReply(ctx, msger, nil, coreSegs, nil, segReq)
}

// validDst return if segReq contains a valid destination for segReq handlers.
func (h *segReqHandler) validDst(segReq *path_mgmt.SegReq) bool {
	// No validation on source here!
	if segReq.DstIA().IsZero() || segReq.DstIA().I == 0 || segReq.DstIA().Eq(h.localIA) {
		h.logger.Warn("[segReqHandler] Drop, invalid dstIA", "dstIA", segReq.DstIA())
		return false
	}
	return true
}

func (h *segReqCoreHandler) coreSegs(ctx context.Context,
	dstIAs []addr.IA) ([]*seg.PathSegment, error) {

	return h.dbSegs(ctx, &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_core},
		StartsAt: dstIAs,
		EndsAt:   []addr.IA{h.localIA},
	})
}

// XXX(lukedirtwalker): copy of segReqHandler version, see comment at fetchAndSaveSegs.
func (h *segReqCoreHandler) downSegs(ctx context.Context,
	msger infra.Messenger, dst addr.IA, dbOnly bool) ([]*seg.PathSegment, error) {

	// try local cache first
	q := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_down},
		EndsAt:   []addr.IA{dst},
	}
	segs, err := h.dbSegs(ctx, q)
	if err != nil {
		return nil, err
	}
	// TODO(lukedirtwalker): also query core if we haven't for a long time.
	if dbOnly || len(segs) > 0 {
		return segs, nil
	}
	_, err = h.fetchAndSaveSegs(ctx, msger, addr.IA{}, dst, requestID.Next())
	if err != nil {
		return nil, err
	}
	// TODO(lukedirtwalker): if fetchAndSaveSegs returns verified segs we don't need to query.
	return h.dbSegs(ctx, q)
}

// XXX(lukedirtwalker): copy of segReqHandler version, corePSAddr is different.
func (h *segReqCoreHandler) fetchAndSaveSegs(ctx context.Context, msger infra.Messenger,
	src, dst addr.IA, id uint64) (*path_mgmt.SegReply, error) {

	cPS, err := h.corePSAddr(ctx, dst.I)
	if err != nil {
		return nil, err
	}
	srcIA := src
	if src.IsZero() {
		srcIA = addr.IA{I: dst.I}
	}
	r := &path_mgmt.SegReq{RawSrcIA: srcIA.IAInt(), RawDstIA: dst.IAInt()}
	segs, err := msger.GetPathSegs(ctx, r, cPS, id)
	if err != nil {
		return nil, err
	}
	h.verifyAndStore(ctx, cPS, ignore, segs.Recs.Recs, segs.Recs.SRevInfos)
	return segs, nil
}

// XXX(lukedirtwalker): very similar to segReqHandler version.
func (h *segReqCoreHandler) corePSAddr(ctx context.Context, destISD addr.ISD) (net.Addr, error) {
	coreSegs, err := h.coreSegs(ctx, []addr.IA{{I: destISD}})
	if err != nil {
		return nil, err
	}
	if len(coreSegs) < 1 {
		return nil, common.NewBasicError("No core segments found!", nil)
	}
	// select random reachable core AS.
	dstIA := coreSegs[rand.Intn(len(coreSegs))].FirstIA()
	paths := combinator.Combine(h.localIA, dstIA, nil, coreSegs, nil)
	if len(paths) < 1 {
		return nil, common.NewBasicError("No path to local cPS", nil)
	}
	return h.addrFromPath(paths, dstIA)
}
