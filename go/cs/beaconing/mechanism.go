package beaconing

import (
	"context"
	"sort"

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/topology"
)

/*
A BeaconingMechanism provides both beacons to propagate and beacons to originate.
RegisterBeacons

*/

type BeaconingMechanism interface {
	// Provides a set of beacons to be propagated
	ProvidePropagationBatch(ctx context.Context, tick Tick) (SendableBeaconsBatch, error)
	// Provides a set of beacons to be originated
	//ProvideOriginationBatch(ctx context.Context) (SendableBeaconsBatch, error)

	// TODO: Implement remaining interfaces
	// Register a new incoming beacon for the mechanism
	//RegisterBeacon(ctx context.Context, beacon beacon.Beacon) error
	// Process a policy update
	//UpdatePolicy(ctx context.Context, policy beacon.Policy) error
	// Return all segments gathered by this mechanism to register at path server
	//SegmentsToRegister(ctx context.Context, segType seg.Type) ([]beacon.Beacon, error)
}

type MechanismBase struct {
	IA                    addr.IA
	AllInterfaces         *ifstate.Interfaces
	PropagationInterfaces func() []*ifstate.Interface
	AllowIsdLoop          bool
	Tick                  Tick
}

func (mb *MechanismBase) getIntfsNeedingBeacons() []*ifstate.Interface {
	intfs := mb.PropagationInterfaces()
	sort.Slice(intfs, func(i, j int) bool {
		return intfs[i].TopoInfo().ID < intfs[j].TopoInfo().ID
	})

	if mb.Tick.Passed() {
		return intfs
	}
	stale := make([]*ifstate.Interface, 0, len(intfs))
	for _, intf := range intfs {
		if mb.Tick.Overdue(intf.LastPropagate()) {
			stale = append(stale, intf)
		}
	}
	return stale
}

func (mb *MechanismBase) GetPeers() []uint16 {
	return sortedIntfs(mb.AllInterfaces, topology.Peer)
}
