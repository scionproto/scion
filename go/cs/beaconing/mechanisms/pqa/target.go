package pqa

import (
	"context"
	"fmt"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	pqa_extension "github.com/scionproto/scion/go/lib/ctrl/seg/extensions/pqabeaconing"
	"github.com/scionproto/scion/go/lib/log"
)

type Target struct {
	Quality    pqa_extension.Quality
	Direction  pqa_extension.Direction
	Uniquifier uint32
	IA         addr.IA
}

func (t Target) String() string {
	return fmt.Sprintf("<%s, %s, %d, %d>", t.Quality, t.Direction, t.Uniquifier, t.IA)
}

// Returns the metric value for a beacon
func (t Target) GetMetric(ctx context.Context, bcn beacon.Beacon) float64 {
	// logger := log.FromCtx(ctx)
	// Holds the result, which will be t.Quality.Combine(m1, t.Quality.Combine(m2, ...))
	// or t.Quality.Infimum() if the beacon has no ASEntries
	res := t.Quality.Infimum()
	for _, entry := range bcn.Segment.ASEntries {
		// Extract metric from this AS Entry
		new_val := t.getMetricFromASEntry(ctx, &entry)
		//		logger.Debug("Extracted metric for as entry", "as", entry.Local, "metric", new_val)
		if res == t.Quality.Infimum() {
			res = new_val
		} else {
			res = t.Quality.Combine(res, new_val)
		}
	}

	// Debug
	if res == t.Quality.Infimum() {
		log.FromCtx(ctx).Info("No AS entries found for target", "target", t)
	}

	//	logger.Debug("Final metric", "metric", res)
	return res
}

// Extracts the metric from the interface ifid to the ifid in the interface in the other AS
func (t Target) getInterASMetric(ctx context.Context, ase *seg.ASEntry, ifid uint16) float64 {
	staticInfo := ase.Extensions.StaticInfo

	ifid_depr := common.IFIDType(ifid)

	var metric float64
	switch t.Quality {
	case pqa_extension.Latency:
		metric = float64(staticInfo.Latency.Inter[ifid_depr].Milliseconds())
	case pqa_extension.Throughput:
		metric = float64(staticInfo.Bandwidth.Inter[ifid_depr])
	default:
		panic("unknown quality")
	}
	return metric
}

// Extracts the metric from the ASEntry egress interface to the interface ifidTo
func (t Target) getIntraASMetric(ctx context.Context, ase *seg.ASEntry, ifidTo uint16) float64 {
	staticInfo := ase.Extensions.StaticInfo

	ifid_depr := common.IFIDType(ifidTo)
	var metric float64
	switch t.Quality {
	case pqa_extension.Latency:
		metric = float64(staticInfo.Latency.Intra[ifid_depr].Milliseconds())
	case pqa_extension.Throughput:
		metric = float64(staticInfo.Bandwidth.Intra[ifid_depr])
	default:
		panic("unknown quality")
	}
	return metric

}

// Extracts metrics from the AS entries, combines them, and returns the metric value
// for an AS entry with ingress interface I and egress E, it returns the metrics
// combine(E -> neighbour of E, I -> E)
func (t Target) getMetricFromASEntry(ctx context.Context, ase *seg.ASEntry) float64 {
	staticInfo := ase.Extensions.StaticInfo

	if staticInfo == nil {
		return t.Quality.Infimum()
	}

	ingIfId := ase.HopEntry.HopField.ConsIngress
	egIfId := ase.HopEntry.HopField.ConsEgress

	interLinkMetric := t.getInterASMetric(ctx, ase, egIfId)
	intraLinkMetric := t.getIntraASMetric(ctx, ase, ingIfId)

	return t.Quality.Combine(interLinkMetric, intraLinkMetric)
}

// Returns ture if target has direction forward or backward,
// or target is symmetric and the metric values are within symmetry tolerance
func (t Target) ShouldConsider(ctx context.Context, bcn beacon.Beacon) bool {
	if t.Direction != pqa_extension.Symmetric {
		return true
	} else {
		log.FromCtx(ctx).Error("Target not supposed to be symmetric.")
		t.Direction = pqa_extension.Forward
		fwd := t.GetMetric(ctx, bcn)

		t.Direction = pqa_extension.Backward
		bwd := t.GetMetric(ctx, bcn)
		if t.Quality.AreSymmetric(fwd, bwd) {
			return true
		} else {
			return false
		}
	}
}
