// Copyright 2019 Anapaya Systems
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

package propagation

import (
	"context"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

// BeaconInserter inserts beacons into the beacon store.
type BeaconInserter interface {
	InsertBeacons(ctx context.Context, beacon ...beacon.Beacon) error
}

// NewHandler returns an infra.Handler for beacon messages. Both the beacon
// inserter and verifier must not be nil. Otherwise, the handler might panic.
func NewHandler(ia addr.IA, infos *ifstate.Infos, beaconInserter BeaconInserter,
	verifier infra.Verifier) infra.Handler {

	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &handler{
			ia:       ia,
			inserter: beaconInserter,
			verifier: verifier,
			infos:    infos,
			request:  r,
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)

}

type handler struct {
	ia       addr.IA
	inserter BeaconInserter
	verifier infra.Verifier
	infos    *ifstate.Infos
	request  *infra.Request
}

// Handle handles a beacon.
func (h *handler) Handle() *infra.HandlerResult {
	logger := log.FromCtx(h.request.Context())
	res, err := h.handle(logger)
	if err != nil {
		logger.Error("[BeaconHandler] Unable to handle beacon", "err", err)
	}
	return res
}

func (h *handler) handle(logger log.Logger) (*infra.HandlerResult, error) {
	bseg, ok := h.request.Message.(*seg.Beacon)
	if !ok {
		return infra.MetricsErrInternal, common.NewBasicError(
			"Wrong message type, expected seg.Beacon", nil,
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
	}
	if err := bseg.Parse(); err != nil {
		return infra.MetricsErrInvalid, common.NewBasicError("Unable to parse beacon", err,
			"beacon", bseg)
	}
	logger.Debug("[BeaconHandler] Received", "beacon", bseg)
	ifid, info, err := h.getIntfInfo()
	if err != nil {
		return infra.MetricsErrInvalid, err
	}
	err = h.validateASEntry(bseg.Segment.ASEntries[bseg.Segment.MaxAEIdx()], ifid, info)
	if err != nil {
		return infra.MetricsErrInvalid, common.NewBasicError("Invalid last AS entry", err,
			"entry", bseg.Segment.ASEntries[bseg.Segment.MaxAEIdx()])
	}
	if err := h.verifySegment(bseg.Segment); err != nil {
		return infra.MetricsErrInvalid, common.NewBasicError("Verification of beacon failed", err)
	}
	b := beacon.Beacon{Segment: bseg.Segment, InIfId: ifid}
	if err := h.inserter.InsertBeacons(h.request.Context(), b); err != nil {
		return infra.MetricsErrInternal, common.NewBasicError("Unable to insert beacon", err)
	}
	logger.Debug("[BeaconHandler] Successfully inserted", "beacon", bseg)
	return infra.MetricsResultOk, nil
}

func (h *handler) getIntfInfo() (common.IFIDType, *ifstate.Info, error) {
	peer, ok := h.request.Peer.(*snet.Addr)
	if !ok {
		return 0, nil, common.NewBasicError("Invalid peer address type, expected *snet.Addr", nil,
			"peer", h.request.Peer, "type", common.TypeOf(h.request.Peer))
	}
	hopF, err := peer.Path.GetHopField(peer.Path.HopOff)
	if err != nil {
		return 0, nil, common.NewBasicError("Unable to extract hop field", err)
	}
	info := h.infos.Get(hopF.ConsIngress)
	if info == nil {
		return 0, nil, common.NewBasicError("Received beacon on non-existent ifid",
			nil, "ifid", hopF.ConsIngress)
	}
	return hopF.ConsIngress, info, nil
}

func (h *handler) validateASEntry(asEntry *seg.ASEntry, ifid common.IFIDType,
	info *ifstate.Info) error {

	topoInfo := info.TopoInfo()
	if topoInfo.LinkType != proto.LinkType_parent && topoInfo.LinkType != proto.LinkType_core {
		return common.NewBasicError("Beacon received on invalid link", nil,
			"ifid", ifid, "linkType", topoInfo.LinkType)
	}
	if !asEntry.IA().Equal(topoInfo.ISD_AS) {
		return common.NewBasicError("Invalid remote IA", nil,
			"expected", topoInfo.ISD_AS, "actual", asEntry.IA())
	}
	for i, hopEntry := range asEntry.HopEntries {
		if !hopEntry.OutIA().Equal(h.ia) {
			return common.NewBasicError("Out IA of hop entry does not match local IA", nil,
				"index", i, "expected", h.ia, "actual", hopEntry.OutIA())
		}
		if hopEntry.RemoteOutIF != ifid {
			return common.NewBasicError("RemoteOutIF of hop entry does not match ingress interface",
				nil, "expected", ifid, "actual", hopEntry.RemoteOutIF)
		}
	}
	return nil
}

func (h *handler) verifySegment(segment *seg.PathSegment) error {
	return segverifier.VerifySegment(h.request.Context(), h.verifier, h.request.Peer, segment)
}
