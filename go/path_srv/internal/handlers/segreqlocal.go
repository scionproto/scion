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
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/pathdb/conn"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

// requestID is used to generate unique request IDs for the messenger.
var requestID messenger.Counter

type segReqLocalHandler struct {
	segReqHandler
}

func NewSegReqLocalHandler(pathDB conn.Conn, revCache revcache.RevCache,
	topology *topology.Topo, trustStore *trust.Store) infra.Handler {

	f := func(r *infra.Request) {
		handler := &segReqLocalHandler{
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
	h.srcTRC, err = h.trustStore.GetTRC(subCtx, h.localIA.I, trust.LatestVersion)
	if err != nil {
		h.logger.Error("[segReqHandler] Failed to get TRC for src", "err", err)
		h.sendEmptySegReply(subCtx, segReq, msger)
		return
	}
	h.dstLocal = segReq.DstIA().I == h.localIA.I
	h.dstCore, err = h.isCoreDst(subCtx, msger, segReq)
	if err != nil {
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
	return h.validDst(segReq)
}

// DD 5.1.1
func (h *segReqLocalHandler) handleCoreDst(ctx context.Context, segReq *path_mgmt.SegReq,
	msger infra.Messenger, dst addr.IA) {

	h.logger.Debug("[segReqHandler] handleCoreDst", "remote", !h.dstLocal)
	upSegs, err := h.upSegs(ctx)
	if err != nil {
		h.logger.Error("Failed to find up segments", "err", err)
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	// TODO(lukedirtwalker): in case of CacheOnly we can use a single query,
	// else we should start go routines for the core segs here.
	var coreSegs []*seg.PathSegment
	for _, src := range firstIAs(upSegs) {
		if !src.Eq(dst) {
			res, err := h.coreSegs(ctx, msger, src, dst, segReq.Flags.CacheOnly)
			if err != nil {
				h.logger.Error("Failed to find core segs", "err", err)
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

	downSegs, err := h.downSegs(ctx, msger, dstIA, segReq.Flags.CacheOnly)
	if err != nil {
		h.logger.Error("Failed to find down segs", "err", err)
		h.sendEmptySegReply(ctx, segReq, msger)
		return
	}
	upSegs, err := h.upSegs(ctx)
	if err != nil {
		h.logger.Error("Failed to find up segs", "err", err)
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
			cs, err := h.coreSegs(ctx, msger, src, dst, segReq.Flags.CacheOnly)
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

func (h *segReqLocalHandler) upSegs(ctx context.Context) ([]*seg.PathSegment, error) {
	cASes := h.srcTRC.CoreASes.ASList()
	return h.dbSegs(ctx, &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_up},
		StartsAt: cASes,
		EndsAt:   []addr.IA{h.localIA},
	})
}

func (h *segReqLocalHandler) coreSegs(ctx context.Context,
	msger infra.Messenger, src, dst addr.IA, dbOnly bool) ([]*seg.PathSegment, error) {

	h.logger.Debug("[segReqHanlder:coreSegs]", "query", fmt.Sprintf("%v->%v", src, dst))
	// try local cache first, inverse query since core segs are stored in inverse direction.
	q := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_core},
		StartsAt: []addr.IA{dst},
		EndsAt:   []addr.IA{src},
	}
	segs, err := h.dbSegs(ctx, q)
	if err != nil {
		return nil, err
	}
	// TODO(lukedirtwalker): also query core if we haven't for a long time.
	if dbOnly || len(segs) > 0 {
		return segs, nil
	}
	// try remote: // TODO here we should pass the cPS we want to ask!
	_, err = h.fetchAndSaveSegs(ctx, msger, src, dst, requestID.Next())
	if err != nil {
		return nil, err
	}
	// TODO(lukedirtwalker): if fetchAndSaveSegs returns verified segs we don't need to query.
	return h.dbSegs(ctx, q)
}

func (h *segReqLocalHandler) downSegs(ctx context.Context,
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
	// TODO(lukedirtwalker): handle expired segments!
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

func (h *segReqLocalHandler) fetchAndSaveSegs(ctx context.Context, msger infra.Messenger,
	src, dst addr.IA, id uint64) (*path_mgmt.SegReply, error) {

	cPS, err := h.corePSAddr(ctx)
	if err != nil {
		return nil, err
	}
	r := &path_mgmt.SegReq{RawSrcIA: src.IAInt(), RawDstIA: dst.IAInt()}
	segs, err := msger.GetPathSegs(ctx, r, cPS, id)
	if err != nil {
		return nil, err
	}
	h.verifyAndStore(ctx, cPS, ignore, segs.Recs.Recs, segs.Recs.SRevInfos)
	return segs, nil
}

func (h *segReqLocalHandler) corePSAddr(ctx context.Context) (net.Addr, error) {
	upSegs, err := h.upSegs(ctx)
	if err != nil {
		return nil, err
	}
	if len(upSegs) < 1 {
		return nil, common.NewBasicError("No up segments found!", nil)
	}
	// select random reachable core AS.
	dstIA := upSegs[rand.Intn(len(upSegs))].FirstIA()
	paths := combinator.Combine(h.localIA, dstIA, upSegs, nil, nil)
	if len(paths) < 1 {
		return nil, common.NewBasicError("No path to local cPS", nil)
	}
	return h.addrFromPath(paths, dstIA)
}
