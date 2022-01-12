package memory

import (
	"sync"

	"github.com/scionproto/scion/go/cs/beaconing/mechanisms/pqa"
)

type TargetSet struct {
	set map[pqa.Target]struct{}
}

func (t *TargetSet) Add(target pqa.Target) {
	t.set[target] = struct{}{}
}

func (t *TargetSet) Remove(target pqa.Target) {
	delete(t.set, target)
}

func (t *TargetSet) Contains(target pqa.Target) bool {
	_, ok := t.set[target]
	return ok
}

type TargetBackend struct {
	mu sync.Mutex
	// Maps beacon row id to targets
	beaconTargetAssoc map[int64]*pqa.Target
	TargetSet
}

func NewTargetBackend() (*TargetBackend, error) {
	return &TargetBackend{
		beaconTargetAssoc: make(map[int64]*pqa.Target),
		TargetSet:         TargetSet{},
	}, nil
}

func (t *TargetBackend) AssociateBeacon(beaconID int64, target pqa.Target) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.beaconTargetAssoc[beaconID] = &target
}
