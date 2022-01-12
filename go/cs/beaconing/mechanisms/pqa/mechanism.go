package pqa

import (
	"context"
	"crypto/rand"
	"math/big"
	"sort"
	"time"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

type Mechanism struct {
	Tick                  beaconing.Tick
	AllInterfaces         *ifstate.Interfaces
	PropagationInterfaces func() []*ifstate.Interface
	OriginationInterfaces func() []*ifstate.Interface
	Settings              Settings

	Extender beaconing.Extender
}

// TODO: Split into files?
/* Origination --------------------------------------------------- */

func (m Mechanism) ProvideOriginationBatch(ctx context.Context, tick beaconing.Tick) (beaconing.SendableBeaconsBatch, error) {
	m.Tick = tick
	m.updateOriginationIntervals(ctx)
	res := make(beaconing.SendableBeaconsBatch, 0)
	intfsNeedingBeacons := filterOverdue(ctx, m.Tick, m.OriginationInterfaces())
	for _, intf := range intfsNeedingBeacons {
		intfId := intf.TopoInfo().ID
		interval := m.Settings.Origination.Intervals[intfId]
		targets := m.getOptimizationTargetsForInterface(ctx, intfId, interval)
		res[intf] = make([]beacon.Beacon, 0)
		for _, target := range targets {
			bcn, err := m.createOriginBeaconForTarget(ctx, intfId, target)
			if err != nil {
				return nil, err
			}
			res[intf] = append(res[intf], bcn)
		}
	}
	return res, nil
}

func filterOverdue(ctx context.Context, tick beaconing.Tick, intfs []*ifstate.Interface) []*ifstate.Interface {
	if tick.Passed() {
		return intfs
	}
	var stale []*ifstate.Interface
	for _, intf := range intfs {
		if tick.Overdue(intf.LastOriginate()) {
			stale = append(stale, intf)
		}
	}
	return stale
}

func (m *Mechanism) createOriginBeaconForTarget(ctx context.Context, intfId uint16, target OptimizationTarget) (beacon.Beacon, error) {
	seg, err := m.createSegment(ctx, m.Tick.Now(), intfId)
	if err != nil {
		return beacon.Beacon{}, serrors.WrapStr("creating segment", err, "egress_interface", intfId, "target", target)
	}

	// Extender.Extend beacon with the target as extension
	extensions := []beaconing.Extension{target}
	if err := m.Extender.Extend(ctx, seg, 0, intfId, nil, extensions); err != nil {
		return beacon.Beacon{}, serrors.WrapStr("extending segment", err)
	}
	log.FromCtx(ctx).Debug("Created origin Beacon for tareget", "target", target, "Extension in first entry", seg.ASEntries[0].Extensions)

	return beacon.Beacon{Segment: seg}, nil
}

func (m *Mechanism) updateOriginationIntervals(ctx context.Context) {
	for ifid := range m.Settings.Origination.Intervals {
		if intf := m.AllInterfaces.Get(ifid); intf != nil {
			if m.Tick.Overdue(intf.LastOriginate()) {
				m.Settings.Origination.Intervals[ifid]++
			}
		}
	}
}

func (m *Mechanism) getOptimizationTargetsForInterface(ctx context.Context, ifid uint16, interval uint) []OptimizationTarget {
	logger := log.FromCtx(ctx)
	origSettings := m.Settings.Origination
	if order, ok := origSettings.Orders[ifid]; ok {
		interval = interval % uint(len(order))
		return origSettings.Orders[ifid][interval]
	} else {
		logger.Info("no target defined for interface", "ifid", ifid, "orders", origSettings.Orders)
		return []OptimizationTarget{{}}
	}

}

func (m *Mechanism) createSegment(ctx context.Context, timestamp time.Time, egIntfId uint16) (*seg.PathSegment, error) {
	segID, err := rand.Int(rand.Reader, big.NewInt(1<<16))
	if err != nil {
		return nil, err
	}

	bseg, err := seg.CreateSegment(timestamp, uint16(segID.Uint64()))
	if err != nil {
		return nil, serrors.WrapStr("creating segment", err)
	}

	return bseg, nil
}

func (m Mechanism) ProvidePropagationBatch(ctx context.Context, tick beaconing.Tick) (beaconing.SendableBeaconsBatch, error) {

	res := make(beaconing.SendableBeaconsBatch, 0)
	for _, target := range m.getTargetsFromReceivesBeacons(ctx) {
		for _, neigh := range m.getNeighbouringASs(ctx) {
			for _, intfSubgroup := range m.getIntfSubgroups(ctx, target, neigh) {
				bcns, err := m.getBatch(ctx, target, intfSubgroup, neigh)
				if err != nil {
					return nil, serrors.WrapStr("getting beacon batch", err)
				}
				for _, bcn := range bcns {
					intf := m.AllInterfaces.Get(bcn.EgIfId)
					res.AppendBeacon(intf, bcn)
				}
			}
		}
	}

	return res, nil
}

func (m Mechanism) getTargetsFromReceivesBeacons(ctx context.Context) []OptimizationTarget {
	return nil
}

func (m Mechanism) getNeighbouringASs(ctx context.Context) []addr.IA {
	return nil
}

func (m Mechanism) getIntfSubgroups(ctx context.Context, target OptimizationTarget, to addr.IA) [][]*ifstate.Interface {
	res := make([][]*ifstate.Interface, 0)
	for _, intfG := range m.getIntfGroups(ctx, target) {
		intfSubg := make([]*ifstate.Interface, 0)
		for _, intf := range intfG {
			// TODO: Figure out how to filter for AS
			intfSubg = append(intfSubg, intf)
		}
		res = append(res, intfSubg)
	}
	return res
}

func (m Mechanism) getIntfGroups(ctx context.Context, target OptimizationTarget) [][]*ifstate.Interface {
	return nil
}

func (m Mechanism) getBatch(ctx context.Context, target OptimizationTarget, egIntfG []*ifstate.Interface, neigh addr.IA) ([]beacon.Beacon, error) {
	batch := make([]beacon.Beacon, 0)
	// Adds a beacon to the final batch
	add := func(bcn beacon.Beacon) {
		batch = append(batch, bcn)
	}
	for _, egIntf := range egIntfG {
		for _, igIntfG := range m.getIntfGroups(ctx, target) {
			nBest := m.getNBestFor(ctx, target, igIntfG, neigh)

			for _, bcn := range nBest {
				var (
					ingress = bcn.InIfId
					egress  = egIntf.TopoInfo().ID
				)
				bcn.EgIfId = egress
				// TODO: peers nil?
				// TODO: extensions nil?
				// Todo: Add extension that extends path based on optimization  quality
				err := m.Extender.Extend(ctx, bcn.Segment, ingress, egress, nil, nil)

				if err != nil {
					return nil, serrors.WrapStr("extending beacons", err, "ingress", ingress, "egress", egress, "seg", bcn.Segment)
				}

				// If direction is symmetric, append only if metric values are within symmetry tolerance
				if target.Direction == Symmetric {
					fwd := m.extractMetric(ctx, bcn, Forward)
					bwd := m.extractMetric(ctx, bcn, Backward)
					if target.Quality.IsWithinSymmetryTolerance(fwd, bwd) {
						add(bcn)
					}
				} else {
					add(bcn)
				}
			}
		}
	}
	return m.getNBest(ctx, target, batch), nil
}

func (m Mechanism) getNBestFor(ctx context.Context, target OptimizationTarget, egIntfG []*ifstate.Interface, neigh addr.IA) []beacon.Beacon {
	return nil
}

func (m Mechanism) extractMetric(ctx context.Context, bcn beacon.Beacon, dir OptimizationDirection) float64 {
	return 0
}

func (m Mechanism) getNBest(ctx context.Context, target OptimizationTarget, bcn []beacon.Beacon) []beacon.Beacon {
	less := func(l, r int) bool {
		lBcn, rBcn := bcn[l], bcn[r]
		lMet, rMet := m.extractMetric(ctx, lBcn, target.Direction), m.extractMetric(ctx, rBcn, target.Direction)
		return target.Quality.Less(lMet, rMet)
	}
	sort.Slice(bcn, less)
	return bcn[:m.Settings.Global.NoPathsPerOptimizationTarget]
}
