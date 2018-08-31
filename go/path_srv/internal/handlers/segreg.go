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
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/proto"
)

type segRegHandler struct {
	*baseHandler
	localIA  addr.IA
	syncDown bool
}

func NewSegRegHandler(args HandlerArgs, syncDown bool) infra.Handler {
	f := func(r *infra.Request) {
		handler := &segRegHandler{
			baseHandler: newBaseHandler(r, args),
			localIA:     args.Topology.ISD_AS,
			syncDown:    syncDown,
		}
		handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *segRegHandler) Handle() {
	segReg, ok := h.request.Message.(*path_mgmt.SegReg)
	if !ok {
		h.logger.Error("[segRegHandler] wrong message type, expected path_mgmt.SegReg",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		return
	}
	if err := segReg.ParseRaw(); err != nil {
		h.logger.Error("[segRegHandler] Failed to parse message", "err", err)
		return
	}
	h.logger.Debug("[segRegHandler] Received message", "seg", segReg.SegRecs)
	subCtx, cancelF := context.WithTimeout(h.request.Context(), HandlerTimeout)
	defer cancelF()
	h.verifyAndStore(subCtx, h.request.Peer, h.forwardDownSegs, segReg.Recs, segReg.SRevInfos)
}

// TODO(lukedirtwalker): what about revocations? In the end version we should forward only after
// the whole verification is done and the segments are stored.
// XXX(lukedirtwalker): if verifyAndStore returns all verified stuff,
// we should send segSync only once.
// TODO(lukedirtwalker): we should use a new context for this. As also commented above,
// it probably makes more sense to only forward after everything has been verified,
// with a new context.
func (h *segRegHandler) forwardDownSegs(ctx context.Context, sm *seg.Meta) {
	if !h.syncDown || sm.Type == proto.PathSegType_core || sm.Type == proto.PathSegType_up {
		return
	}
	// down segment needs to be forwarded:
	msger, ok := infra.MessengerFromContext(h.request.Context())
	if !ok {
		h.logger.Error("[forwardDownSegs] no Messenger found")
		return
	}
	trc, err := h.trustStore.GetTRC(ctx, h.localIA.I, scrypto.LatestVer)
	if err != nil {
		h.logger.Error("[forwardDownSegs]", "err", err)
		return
	}
	segSync := &path_mgmt.SegSync{
		SegRecs: &path_mgmt.SegRecs{
			Recs: []*seg.Meta{sm},
		},
	}
	for _, coreIA := range trc.CoreASes.ASList() {
		if coreIA == h.localIA {
			continue
		}
		// TODO(lukedirtwalker): Use go routines here, send is blocking.
		cPS, err := h.corePSAddr(ctx, coreIA)
		if err != nil {
			h.logger.Error("[forwardDownSegs] failed to get path to core",
				"dstIA", coreIA, "err", err)
			continue
		}
		if err := msger.SendSegSync(ctx, segSync, cPS, h.request.ID); err != nil {
			h.logger.Error("[forwardDownSegs] failed to send segSync",
				"dstIA", coreIA, "err", err)
		}
	}
}

func (h *segRegHandler) corePSAddr(ctx context.Context, dstIA addr.IA) (net.Addr, error) {
	coreSegs, err := h.fetchSegsFromDB(ctx, &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_core},
		StartsAt: []addr.IA{dstIA},
		EndsAt:   []addr.IA{h.localIA},
	})
	if err != nil {
		return nil, err
	}
	if len(coreSegs) == 0 {
		return nil, common.NewBasicError("No core segments found!", nil)
	}
	seg := coreSegs[rand.Intn(len(coreSegs))]
	return h.psAddrFromSeg(seg, seg.FirstIA())
}
