package pqa

import (
	"context"
	"crypto/rand"
	"math/big"
	"time"

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
	Settings
	DB

	Extender beaconing.Extender
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

func (m *Mechanism) UpdateOriginationIntervals(ctx context.Context) {
	for ifid := range m.Settings.Origination.Intervals {
		if intf := m.AllInterfaces.Get(ifid); intf != nil {
			if m.Tick.Overdue(intf.LastOriginate()) {
				m.Settings.Origination.Intervals[ifid]++
			}
		}
	}
}

func (m *Mechanism) getOptimizationTargetsForInterface(ctx context.Context, ifid uint16, interval uint) []Target {
	logger := log.FromCtx(ctx)
	origSettings := m.Settings.Origination
	if order, ok := origSettings.Orders[ifid]; ok {
		interval = interval % uint(len(order))
		return origSettings.Orders[ifid][interval]
	} else {
		logger.Info("no target defined for interface", "ifid", ifid, "orders", origSettings.Orders)
		return []Target{}
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
