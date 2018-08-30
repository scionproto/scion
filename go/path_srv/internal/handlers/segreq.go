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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/path_srv/internal/segutil"
	"github.com/scionproto/scion/go/proto"
)

type segReqHandler struct {
	*baseHandler
	localIA addr.IA
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
	if segReq.DstIA().IsZero() || segReq.DstIA().I == 0 || segReq.DstIA().Eq(h.localIA) {
		h.logger.Warn("[segReqHandler] Drop, invalid dstIA", "dstIA", segReq.DstIA())
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

func (h *segReqHandler) fetchDownSegs(ctx context.Context,
	msger infra.Messenger, dst addr.IA, cPSAddr net.Addr, dbOnly bool) (seg.Segments, error) {

	// try local cache first
	q := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_down},
		EndsAt:   []addr.IA{dst},
	}
	segs, err := h.fetchSegsFromDB(ctx, q)
	if err != nil {
		return nil, err
	}
	// TODO(lukedirtwalker): also query core if we haven't for a long time.
	// TODO(lukedirtwalker): handle expired segments!
	if dbOnly || len(segs) > 0 {
		return segs, nil
	}
	if err = h.fetchAndSaveSegs(ctx, msger, addr.IA{}, dst, cPSAddr); err != nil {
		return nil, err
	}
	// TODO(lukedirtwalker): if fetchAndSaveSegs returns verified segs we don't need to query.
	return h.fetchSegsFromDB(ctx, q)
}

func (h *segReqHandler) fetchAndSaveSegs(ctx context.Context, msger infra.Messenger,
	src, dst addr.IA, cPSAddr net.Addr) error {

	r := &path_mgmt.SegReq{RawSrcIA: src.IAInt(), RawDstIA: dst.IAInt()}
	segs, err := msger.GetSegs(ctx, r, cPSAddr, requestID.Next())
	if err != nil {
		return err
	}
	var recs []*seg.Meta
	var revInfos []*path_mgmt.SignedRevInfo
	if segs.Recs != nil {
		recs = segs.Recs.Recs
		revInfos = segs.Recs.SRevInfos
		h.verifyAndStore(ctx, cPSAddr, recs, revInfos)
	}
	return nil
}

func (h *segReqHandler) sendReply(ctx context.Context, msger infra.Messenger,
	upSegs, coreSegs, downSegs []*seg.PathSegment, segReq *path_mgmt.SegReq) {

	recs := &path_mgmt.SegRecs{
		Recs:      h.collectSegs(upSegs, coreSegs, downSegs),
		SRevInfos: segutil.RelevantRevInfos(h.revCache, upSegs, coreSegs, downSegs),
	}
	reply := &path_mgmt.SegReply{
		Req:  segReq,
		Recs: recs,
	}
	err := msger.SendSegReply(ctx, reply, h.request.Peer, h.request.ID)
	if err != nil {
		h.logger.Error("[segReqHandler] Failed to send reply!", "err", err)
	}
	h.logger.Debug("[segReqHandler] reply sent", "id", h.request.ID)
}

func (h *segReqHandler) collectSegs(upSegs, coreSegs, downSegs []*seg.PathSegment) []*seg.Meta {
	recs := make([]*seg.Meta, 0, len(upSegs)+len(coreSegs)+len(downSegs))
	for i := range upSegs {
		s := upSegs[i]
		h.logger.Debug(fmt.Sprintf("[segReqHandler:collectSegs] up %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs = append(recs, seg.NewMeta(s, proto.PathSegType_up))
	}
	for i := range coreSegs {
		s := coreSegs[i]
		h.logger.Debug(fmt.Sprintf("[segReqHandler:collectSegs] core %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs = append(recs, seg.NewMeta(s, proto.PathSegType_core))
	}
	for i := range downSegs {
		s := downSegs[i]
		h.logger.Debug(fmt.Sprintf("[segReqHandler:collectSegs] down %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs = append(recs, seg.NewMeta(s, proto.PathSegType_down))
	}
	return recs
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
