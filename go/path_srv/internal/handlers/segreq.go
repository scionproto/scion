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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/proto"
)

type segReqHandler struct {
	baseHandler
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
	dstTRC, err := h.trustStore.GetTRC(ctx, segReq.DstIA().I, trust.LatestVersion)
	if err != nil {
		h.logger.Error("[segReqHandler] Failed to get TRC for dst", "err", err)
		h.sendEmptySegReply(ctx, segReq, msger)
		return false, err
	}
	return dstTRC.CoreASes.Contains(segReq.DstIA()), nil
}

func (h *segReqHandler) sendReply(ctx context.Context, msger infra.Messenger,
	upSegs, coreSegs, downSegs []*seg.PathSegment, segReq *path_mgmt.SegReq) {

	upSegs, coreSegs, downSegs = checkConnected(upSegs, coreSegs, downSegs)
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
		recs[i] = &seg.Meta{Type: proto.PathSegType_up, Segment: *upSegs[i]}
	}
	l := len(upSegs)
	for i, s := range coreSegs {
		h.logger.Debug(fmt.Sprintf("[segReqHandler:collectSegs] core %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs[l+i] = &seg.Meta{Type: proto.PathSegType_core, Segment: *coreSegs[i]}
	}
	l = len(upSegs) + len(coreSegs)
	for i, s := range downSegs {
		h.logger.Debug(fmt.Sprintf("[segReqHandler:collectSegs] down %v -> %v",
			s.FirstIA(), s.LastIA()))
		recs[l+i] = &seg.Meta{Type: proto.PathSegType_down, Segment: *downSegs[i]}
	}
	return recs
}

func segMap(segs []*seg.PathSegment,
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

// remove down/up segs that have no corresponding core seg.
func checkConnected(upSegs, coreSegs, downSegs []*seg.PathSegment) ([]*seg.PathSegment,
	[]*seg.PathSegment, []*seg.PathSegment) {

	upCount := len(upSegs)
	downCount := len(downSegs)
	ups := segMap(upSegs, firstIA)
	downs := segMap(downSegs, firstIA)
	// remove unconnected core segs
	coreSegs = filterSegs(coreSegs, func(s *seg.PathSegment) bool {
		_, upExists := ups[s.LastIA()]
		_, downExists := downs[s.FirstIA()]
		return (upCount == 0 || upExists) &&
			(downCount == 0 || downExists)
	})
	coreUps := segMap(coreSegs, lastIA)
	coreDowns := segMap(coreSegs, firstIA)
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
	addRevKeys(upSegs, revKeys)
	addRevKeys(coreSegs, revKeys)
	addRevKeys(downSegs, revKeys)
	return revKeys
}

func addRevKeys(segs []*seg.PathSegment, keys map[revcache.Key]struct{}) {
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
					keys[*revcache.NewKey(asEntry.IA(), hf.ConsIngress)] = empty
				}
				if hf.ConsEgress != 0 {
					keys[*revcache.NewKey(asEntry.IA(), hf.ConsEgress)] = empty
				}
			}
		}
	}
}
