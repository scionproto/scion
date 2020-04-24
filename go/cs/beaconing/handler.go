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

package beaconing

import (
	"context"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

// BeaconInserter inserts beacons into the beacon store.
type BeaconInserter interface {
	PreFilter(beacon beacon.Beacon) error
	InsertBeacon(ctx context.Context, beacon beacon.Beacon) (beacon.InsertStats, error)
}

// NewHandler returns an infra.Handler for beacon messages. Both the beacon
// inserter and verifier must not be nil. Otherwise, the handler might panic.
func NewHandler(ia addr.IA, intfs *ifstate.Interfaces, beaconInserter BeaconInserter,
	verifier infra.Verifier) infra.Handler {

	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &handler{
			ia:       ia,
			inserter: beaconInserter,
			verifier: verifier,
			intfs:    intfs,
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
	intfs    *ifstate.Interfaces
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
	rw, ok := infra.ResponseWriterFromContext(h.request.Context())
	if !ok {
		return infra.MetricsErrInternal, serrors.New("No Messenger found")
	}

	sendAck := messenger.SendAckHelper(h.request.Context(), rw)

	labels := metrics.BeaconingLabels{}
	ifid, as, err := h.getIFID()
	if err != nil {
		metrics.Beaconing.Received(labels.WithResult(metrics.ErrParse)).Inc()
		return infra.MetricsErrInvalid, err
	}
	labels.InIfID, labels.NeighIA = ifid, as
	b, res, err := h.buildBeacon(ifid)
	if err != nil {
		metrics.Beaconing.Received(labels.WithResult(metrics.ErrParse)).Inc()
		return res, err
	}
	logger.Trace("[BeaconHandler] Received", "beacon", b)
	if err := h.inserter.PreFilter(b); err != nil {
		logger.Trace("[BeaconHandler] Beacon pre-filtered", "err", err)
		metrics.Beaconing.Received(labels.WithResult(metrics.ErrPrefilter)).Inc()
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectPolicyError)
		return infra.MetricsErrInvalid, nil
	}
	if err := h.verifyBeacon(b); err != nil {
		logger.Trace("[BeaconHandler] Beacon verification", "err", err)
		metrics.Beaconing.Received(labels.WithResult(metrics.ErrVerify)).Inc()
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToVerify)
		return infra.MetricsErrInvalid, err
	}
	stat, err := h.inserter.InsertBeacon(h.request.Context(), b)
	if err != nil {
		metrics.Beaconing.Received(labels.WithResult(metrics.ErrDB)).Inc()
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRetryDBError)
		return infra.MetricsErrInternal, common.NewBasicError("Unable to insert beacon", err)
	}
	logger.Trace("[BeaconHandler] Successfully inserted", "beacon", b)
	metrics.Beaconing.Received(labels.WithResult(
		metrics.GetResultValue(stat.Inserted, stat.Updated, stat.Filtered))).Inc()
	sendAck(proto.Ack_ErrCode_ok, "")
	return infra.MetricsResultOk, nil
}

func (h *handler) buildBeacon(ifid common.IFIDType) (beacon.Beacon, *infra.HandlerResult, error) {
	pseg, ok := h.request.Message.(*seg.PathSegment)
	if !ok {
		return beacon.Beacon{}, infra.MetricsErrInternal, common.NewBasicError(
			"Wrong message type, expected *seg.PathSegment", nil,
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
	}
	if err := pseg.ParseRaw(seg.ValidateBeacon); err != nil {
		return beacon.Beacon{}, infra.MetricsErrInvalid,
			common.NewBasicError("Unable to parse beacon", err, "beacon", pseg)
	}
	return beacon.Beacon{InIfId: ifid, Segment: pseg}, nil, nil
}

func (h *handler) getIFID() (common.IFIDType, addr.IA, error) {
	var ia addr.IA
	peer, ok := h.request.Peer.(*snet.UDPAddr)
	if !ok {
		return 0, ia, common.NewBasicError("Invalid peer address type, expected *snet.UDPAddr", nil,
			"peer", h.request.Peer, "type", common.TypeOf(h.request.Peer))
	}
	hopF, err := peer.Path.GetHopField(peer.Path.HopOff)
	if err != nil {
		return 0, ia, common.NewBasicError("Unable to extract hop field", err)
	}
	intf := h.intfs.Get(hopF.ConsIngress)
	if intf == nil {
		return 0, ia, common.NewBasicError("Received beacon on non-existent ifid", nil,
			"ifid", hopF.ConsIngress)
	}
	return hopF.ConsIngress, intf.TopoInfo().IA, nil
}

func (h *handler) verifyBeacon(b beacon.Beacon) error {
	if err := h.validateASEntry(b); err != nil {
		return common.NewBasicError("Invalid last AS entry", err,
			"entry", b.Segment.ASEntries[b.Segment.MaxAEIdx()])
	}
	if err := h.verifySegment(b.Segment); err != nil {
		return common.NewBasicError("Verification of beacon failed", err)
	}
	return nil
}

func (h *handler) validateASEntry(b beacon.Beacon) error {
	intf := h.intfs.Get(b.InIfId)
	if intf == nil {
		return common.NewBasicError("Received beacon on non-existent ifid", nil, "ifid", b.InIfId)
	}
	topoInfo := intf.TopoInfo()
	if topoInfo.LinkType != topology.Parent && topoInfo.LinkType != topology.Core {
		return common.NewBasicError("Beacon received on invalid link", nil,
			"ifid", b.InIfId, "linkType", topoInfo.LinkType)
	}
	asEntry := b.Segment.ASEntries[b.Segment.MaxAEIdx()]
	if !asEntry.IA().Equal(topoInfo.IA) {
		return common.NewBasicError("Invalid remote IA", nil,
			"expected", topoInfo.IA, "actual", asEntry.IA())
	}
	for i, hopEntry := range asEntry.HopEntries {
		if !hopEntry.OutIA().Equal(h.ia) {
			return common.NewBasicError("Out IA of hop entry does not match local IA", nil,
				"index", i, "expected", h.ia, "actual", hopEntry.OutIA())
		}
		if hopEntry.RemoteOutIF != b.InIfId {
			return common.NewBasicError("RemoteOutIF of hop entry does not match ingress interface",
				nil, "expected", b.InIfId, "actual", hopEntry.RemoteOutIF)
		}
	}
	return nil
}

func (h *handler) verifySegment(segment *seg.PathSegment) error {
	snetPeer := h.request.Peer.(*snet.UDPAddr)
	peerPath, err := snetPeer.GetPath()
	if err != nil {
		return common.NewBasicError("path error", err)
	}
	svcToQuery := &snet.SVCAddr{
		IA:      snetPeer.IA,
		Path:    peerPath.Path(),
		NextHop: peerPath.UnderlayNextHop(),
		SVC:     addr.SvcBS,
	}
	return segverifier.VerifySegment(h.request.Context(), h.verifier, svcToQuery, segment)
}
