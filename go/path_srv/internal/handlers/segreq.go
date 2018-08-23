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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/pathdb/query"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/proto"
)

type segReqHandler struct {
	*baseHandler
	localIA  addr.IA
	srcTRC   *trc.TRC
	dstLocal bool
	dstCore  bool
}

func (h *segReqHandler) sendEmptySegReply(ctx context.Context,
	segReq *path_mgmt.SegReq, msger infra.Messenger) {

	msger.SendSegReply(ctx, &path_mgmt.SegReply{Req: segReq, Recs: nil},
		h.request.Peer, h.request.ID)
}

func (h *segReqHandler) isCoreDst(ctx context.Context, msger infra.Messenger,
	segReq *path_mgmt.SegReq) (bool, error) {

	if segReq.DstIA().A == 0 {
		return true, nil
	}
	if h.dstLocal {
		return h.srcTRC.CoreASes.Contains(segReq.DstIA()), nil
	}
	dstTRC, err := h.trustStore.GetTRC(ctx, segReq.DstIA().I, 0)
	if err != nil {
		return false, common.NewBasicError("Failed to get TRC for dst", err)
	}
	return dstTRC.CoreASes.Contains(segReq.DstIA()), nil
}

func (h *segReqHandler) fetchDownSegs(ctx context.Context,
	msger infra.Messenger, dst addr.IA, cPSAddr net.Addr, dbOnly bool) ([]*seg.PathSegment, error) {

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

	_, err = h.fetchAndSaveSegs(ctx, msger, addr.IA{}, dst, cPSAddr, requestID.Next())
	if err != nil {
		return nil, err
	}
	// TODO(lukedirtwalker): if fetchAndSaveSegs returns verified segs we don't need to query.
	return h.fetchSegsFromDB(ctx, q)
}

func (h *segReqHandler) fetchAndSaveSegs(ctx context.Context, msger infra.Messenger,
	src, dst addr.IA, cPSAddr net.Addr, id uint64) (*path_mgmt.SegReply, error) {

	r := &path_mgmt.SegReq{RawSrcIA: src.IAInt(), RawDstIA: dst.IAInt()}
	segs, err := msger.GetPathSegs(ctx, r, cPSAddr, id)
	if err != nil {
		return nil, err
	}
	var recs []*seg.Meta
	var revInfos []*path_mgmt.SignedRevInfo
	if segs.Recs != nil {
		recs = segs.Recs.Recs
		revInfos = segs.Recs.SRevInfos
	}
	h.verifyAndStore(ctx, cPSAddr, ignore, recs, revInfos)
	return segs, nil
}

func (h *segReqHandler) sendReply(ctx context.Context, msger infra.Messenger,
	upSegs, coreSegs, downSegs []*seg.PathSegment, segReq *path_mgmt.SegReq) {

	upSegs, coreSegs, downSegs = removeDisconnectedSegs(upSegs, coreSegs, downSegs)
	recs := &path_mgmt.SegRecs{
		Recs:      h.collectSegs(upSegs, coreSegs, downSegs),
		SRevInfos: h.relevantRevInfos(upSegs, coreSegs, downSegs),
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

func (h *segReqHandler) relevantRevInfos(upSegs, coreSegs,
	downSegs []*seg.PathSegment) []*path_mgmt.SignedRevInfo {

	revKeys := allRevKeys(upSegs, coreSegs, downSegs)
	var revs []*path_mgmt.SignedRevInfo
	for rk := range revKeys {
		if revInfo, ok := h.revCache.Get(&rk); ok {
			revs = append(revs, revInfo)
		}
	}
	return revs
}

func (h *segReqHandler) collectSegs(upSegs, coreSegs, downSegs []*seg.PathSegment) []*seg.Meta {
	recs := make([]*seg.Meta, len(upSegs)+len(coreSegs)+len(downSegs))
	for i, s := range upSegs {
		h.logger.Debug(fmt.Sprintf("[segReqHandler:collectSegs] up %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs[i] = &seg.Meta{Type: proto.PathSegType_up, Segment: upSegs[i]}
	}
	l := len(upSegs)
	for i, s := range coreSegs {
		h.logger.Debug(fmt.Sprintf("[segReqHandler:collectSegs] core %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs[l+i] = &seg.Meta{Type: proto.PathSegType_core, Segment: coreSegs[i]}
	}
	l = len(upSegs) + len(coreSegs)
	for i, s := range downSegs {
		h.logger.Debug(fmt.Sprintf("[segReqHandler:collectSegs] down %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs[l+i] = &seg.Meta{Type: proto.PathSegType_down, Segment: downSegs[i]}
	}
	return recs
}

// segsToMap converts the segs slice to a map of IAs to segments.
// The IA (key) is selected using the key function.
func segsToMap(segs []*seg.PathSegment,
	key func(*seg.PathSegment) addr.IA) map[addr.IA][]*seg.PathSegment {

	if len(segs) == 0 {
		return nil
	}
	res := make(map[addr.IA][]*seg.PathSegment)
	for _, s := range segs {
		res[key(s)] = append(res[key(s)], s)
	}
	return res
}

// removeDisconnectedSegs removes down/up segs that have no corresponding core seg.
func removeDisconnectedSegs(upSegs, coreSegs, downSegs []*seg.PathSegment) ([]*seg.PathSegment,
	[]*seg.PathSegment, []*seg.PathSegment) {

	upCount := len(upSegs)
	downCount := len(downSegs)
	ups := segsToMap(upSegs, firstIA)
	downs := segsToMap(downSegs, firstIA)
	// remove unconnected core segs
	coreSegs = filterSegs(coreSegs, func(s *seg.PathSegment) bool {
		_, upExists := ups[s.LastIA()]
		_, downExists := downs[s.FirstIA()]
		return (upCount == 0 || upExists) &&
			(downCount == 0 || downExists)
	})
	coreUps := segsToMap(coreSegs, lastIA)
	coreDowns := segsToMap(coreSegs, firstIA)
	// If we have both up and down segments there has to be some connection via a core AS.
	coreHasToExist := upCount > 0 && downCount > 0
	// remove unconnected up segs
	upSegs = filterSegs(upSegs, func(s *seg.PathSegment) bool {
		_, coreExists := coreUps[s.FirstIA()]
		_, downExists := downs[s.FirstIA()]
		return (!coreHasToExist && len(coreSegs) == 0) || coreExists || downExists
	})
	// remove unconnected down segs
	downSegs = filterSegs(downSegs, func(s *seg.PathSegment) bool {
		_, coreExists := coreDowns[s.FirstIA()]
		_, upExists := ups[s.FirstIA()]
		return (!coreHasToExist && len(coreSegs) == 0) || coreExists || upExists
	})
	return upSegs, coreSegs, downSegs
}

func allRevKeys(upSegs, coreSegs, downSegs []*seg.PathSegment) map[revcache.Key]struct{} {
	revKeys := make(map[revcache.Key]struct{}, 2*(len(upSegs)+len(coreSegs)+len(downSegs)))
	addRevKeys(upSegs, revKeys, false)
	addRevKeys(coreSegs, revKeys, false)
	addRevKeys(downSegs, revKeys, false)
	return revKeys
}

// addRevKeys adds all revocations keys for the given segments to the keys set.
// If hopOnly is set, only the first hop entry is considered.
func addRevKeys(segs []*seg.PathSegment, keys map[revcache.Key]struct{}, hopOnly bool) {
	for _, s := range segs {
		for _, asEntry := range s.ASEntries {
			for _, entry := range asEntry.HopEntries {
				hf, err := entry.HopField()
				if err != nil {
					// This should not happen, as Validate already checks that it
					// is possible to extract the hop field.
					panic(err)
				}
				if hf.ConsIngress != 0 {
					keys[*revcache.NewKey(asEntry.IA(), hf.ConsIngress)] = struct{}{}
				}
				if hf.ConsEgress != 0 {
					keys[*revcache.NewKey(asEntry.IA(), hf.ConsEgress)] = struct{}{}
				}
				if hopOnly {
					break
				}
			}
		}
	}
}
