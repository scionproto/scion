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
	"strconv"

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/ifstate"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/segment/segverifier"
	infra "github.com/scionproto/scion/private/segment/verifier"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/tracing"
)

// BeaconInserter inserts beacons into the beacon store.
type BeaconInserter interface {
	PreFilter(beacon beacon.Beacon) error
	InsertBeacon(ctx context.Context, beacon beacon.Beacon) (beacon.InsertStats, error)
}

// Handler handles beacons.
type Handler struct {
	LocalIA    addr.IA
	Inserter   BeaconInserter
	Verifier   infra.Verifier
	Interfaces *ifstate.Interfaces

	BeaconsHandled metrics.Counter
}

// HandleBeacon handles a baeacon received from peer.
func (h Handler) HandleBeacon(ctx context.Context, b beacon.Beacon, peer *snet.UDPAddr) error {
	span := opentracing.SpanFromContext(ctx)
	labels := handlerLabels{Ingress: b.InIfID}

	intf := h.Interfaces.Get(b.InIfID)
	if intf == nil {
		err := serrors.New("received beacon on non-existent interface",
			"ingress_interface", b.InIfID)
		h.updateMetric(span, labels.WithResult(prom.ErrNotClassified), err)
		return err
	}

	upstream := intf.TopoInfo().IA
	if span != nil {
		span.SetTag("ingress_interface", b.InIfID)
		span.SetTag("upstream", upstream)
	}
	labels.Neighbor = upstream
	logger := log.FromCtx(ctx).New("beacon", b, "upstream", upstream)
	ctx = log.CtxWith(ctx, logger)

	logger.Debug("Received beacon")
	if err := h.Inserter.PreFilter(b); err != nil {
		logger.Debug("Beacon pre-filtered", "err", err)
		h.updateMetric(span, labels.WithResult("err_prefilter"), err)
		return err
	}
	if err := h.validateASEntry(b, intf); err != nil {
		logger.Info("Beacon validation failed", "err", err)
		h.updateMetric(span, labels.WithResult(prom.ErrVerify), err)
		return err
	}
	if err := h.verifySegment(ctx, b.Segment, peer); err != nil {
		logger.Info("Beacon verification failed", "err", err)
		h.updateMetric(span, labels.WithResult(prom.ErrVerify), err)
		return serrors.Wrap("verifying beacon", err)
	}
	stat, err := h.Inserter.InsertBeacon(ctx, b)
	if err != nil {
		logger.Debug("Failed to insert beacon", "err", err)
		h.updateMetric(span, labels.WithResult(prom.ErrDB), err)
		return serrors.Wrap("inserting beacon", err)

	}
	labels = labels.WithResult(resultValue(stat.Inserted, stat.Updated, stat.Filtered))
	h.updateMetric(span, labels, err)
	logger.Debug("Inserted beacon")
	return nil
}

func (h Handler) validateASEntry(b beacon.Beacon, intf *ifstate.Interface) error {
	topoInfo := intf.TopoInfo()
	if topoInfo.LinkType != topology.Parent && topoInfo.LinkType != topology.Core {
		return serrors.New("beacon received on invalid link",
			"ingress_interface", b.InIfID, "link_type", topoInfo.LinkType)
	}
	asEntry := b.Segment.ASEntries[b.Segment.MaxIdx()]
	if !asEntry.Local.Equal(topoInfo.IA) {
		return serrors.New("invalid upstream ISD-AS",
			"expected", topoInfo.IA, "actual", asEntry.Local)
	}
	if !asEntry.Next.Equal(h.LocalIA) {
		return serrors.New("next ISD-AS of upstream AS entry does not match local ISD-AS",
			"expected", h.LocalIA, "actual", asEntry.Next)
	}
	return nil
}

func (h Handler) verifySegment(ctx context.Context, segment *seg.PathSegment,
	peer *snet.UDPAddr) error {

	peerPath, err := peer.GetPath()
	if err != nil {
		return err
	}
	svcToQuery := &snet.SVCAddr{
		IA:      peer.IA,
		Path:    peerPath.Dataplane(),
		NextHop: peerPath.UnderlayNextHop(),
		SVC:     addr.SvcCS,
	}
	return segverifier.VerifySegment(ctx, h.Verifier, svcToQuery, segment)
}

func (h Handler) updateMetric(span opentracing.Span, l handlerLabels, err error) {
	if h.BeaconsHandled != nil {
		h.BeaconsHandled.With(l.Expand()...).Add(1)
	}
	if span != nil {
		tracing.ResultLabel(span, l.Result)
		tracing.Error(span, err)
	}
}

type handlerLabels struct {
	Ingress  uint16
	Neighbor addr.IA
	Result   string
}

func (l handlerLabels) Expand() []string {
	return []string{
		"ingress_interface", strconv.Itoa(int(l.Ingress)),
		prom.LabelNeighIA, l.Neighbor.String(),
		prom.LabelResult, l.Result,
	}
}

func (l handlerLabels) WithResult(result string) handlerLabels {
	l.Result = result
	return l
}

func resultValue(ins, upd, flt int) string {
	switch {
	case flt > 0:
		return "ok_filtered"
	case upd > 0:
		return "ok_updated"
	case ins > 0:
		return "ok_new"
	default:
		return "ok_old"
	}
}
