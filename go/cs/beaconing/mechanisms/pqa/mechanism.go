package pqa

import (
	"context"
	"crypto/rand"
	"math/big"
	"time"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/cs/ifstate"
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

func (m Mechanism) ProvidePropagationBatch(ctx context.Context, tick beaconing.Tick) (beaconing.SendableBeaconsBatch, error) {
	return nil, serrors.New("not yet implemented")
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

func (m *Mechanism) writePqaExtension(ctx context.Context, bseg *seg.PathSegment, target OptimizationTarget) error {

	return nil
}
