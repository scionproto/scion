package targetstore

import (
	"context"
	"sync"

	"github.com/scionproto/scion/go/cs/beaconing/mechanisms/pqa"
	"github.com/scionproto/scion/go/lib/addr"
)

type Targets struct {
	sync.RWMutex
	// maps beaconID -> target 1:1
	beaconTargetMap map[int64]pqa.Target
	// maps target -> beacons 1:n, implicitly keeps track of all targets
	targetBeaconsMap map[pqa.Target]map[int64]bool
}

func NewTargetBackend() (*Targets, error) {
	return &Targets{
		beaconTargetMap:  make(map[int64]pqa.Target),
		targetBeaconsMap: make(map[pqa.Target]map[int64]bool),
	}, nil
}

func (t *Targets) AssociateBeacon(beaconID int64, target pqa.Target) {
	t.Lock()
	defer t.Unlock()

	// Associate beacon with target
	t.beaconTargetMap[beaconID] = target

	// Associate target with beacon:
	if t.targetBeaconsMap[target] == nil {
		t.targetBeaconsMap[target] = make(map[int64]bool)
	}
	t.targetBeaconsMap[target][beaconID] = true
}
func (t *Targets) GetActiveTargets(ctx context.Context, src addr.IA) ([]pqa.Target, error) {
	t.RLock()
	defer t.RUnlock()

	res := make([]pqa.Target, 0, len(t.targetBeaconsMap))
	for target := range t.targetBeaconsMap {
		if src.Equal(target.IA) {
			res = append(res, target)
		}
	}
	return res, nil
}

func (t *Targets) GetBeaconIdsForTarget(ctx context.Context, target pqa.Target) []int64 {
	t.RLock()
	defer t.RUnlock()
	res := make([]int64, 0, len(t.targetBeaconsMap[target]))
	for beaconID := range t.targetBeaconsMap[target] {
		res = append(res, beaconID)
	}

	return res
}
