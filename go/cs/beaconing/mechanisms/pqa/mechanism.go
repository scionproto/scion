package pqa

import (
	"context"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

type Mechanism struct {
	Tick                  beaconing.Tick
	AllInterfaces         *ifstate.Interfaces
	PropagationInterfaces func() []*ifstate.Interface
	OriginationInterfaces func() []*ifstate.Interface
	Settings
	DB

	Extender beaconing.Extender
}

func (m Mechanism) ProvidePropagationBatch(ctx context.Context, tick beaconing.Tick) (beaconing.SendableBeaconsBatch, error) {
	logger := log.FromCtx(ctx)
	if !tick.Passed() {
		return beaconing.SendableBeaconsBatch{}, nil
	}
	res := make(beaconing.SendableBeaconsBatch, 0)
	for _, srcIA := range m.getSourceIAs(ctx) {
		for _, target := range m.getTargetsFromReceivedBeacons(ctx, srcIA) {
			for _, neigh := range m.getNeighbouringASs(ctx) {
				for _, intfSubgroup := range m.getIntfSubgroups(ctx, target, neigh) {
					// logger.Debug("finding batch for", "src ia", srcIA, "target", target, "neigh", neigh, "intf subgroup", intfSubgroup)
					bcns, err := m.getPropagationBatch(ctx, target, intfSubgroup, neigh, srcIA)
					// logger.Debug("found batch:", "bcns", len(bcns))
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
	}
	logger.Debug("returning batch of size", "size", len(res))
	return res, nil
}

func (m Mechanism) ProvideOriginationBatch(ctx context.Context, tick beaconing.Tick) (beaconing.SendableBeaconsBatch, error) {
	m.Tick = tick
	m.UpdateOriginationIntervals(ctx)
	res := make(beaconing.SendableBeaconsBatch, 0)
	intfsNeedingBeacons := filterOverdue(ctx, m.Tick, m.OriginationInterfaces())
	for _, intf := range intfsNeedingBeacons {
		intfId := intf.TopoInfo().ID
		interval := m.Settings.Origination.Intervals[intfId]
		targets := m.getOptimizationTargetsForInterface(ctx, intfId, interval)
		res[intf] = make([]beacon.Beacon, 0)
		for _, target := range targets {
			bcn, err := m.CreateOriginBeaconForTarget(ctx, intfId, target)
			if err != nil {
				return nil, err
			}
			res[intf] = append(res[intf], bcn)
		}
	}
	return res, nil
}
