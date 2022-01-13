package pqa

import (
	"context"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

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

func (m *Mechanism) CreateOriginBeaconForTarget(ctx context.Context, intfId uint16, target Target) (beacon.Beacon, error) {
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
