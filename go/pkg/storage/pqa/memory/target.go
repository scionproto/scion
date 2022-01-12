package memory

import (
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	pqa_extension "github.com/scionproto/scion/go/lib/ctrl/seg/extensions/pqabeaconing"
)

type Target struct {
	Quality    pqa_extension.Quality
	Direction  pqa_extension.Direction
	Uniquifier uint32
	ISD        addr.ISD
	AS         addr.AS
}

type TargetSet struct {
	set map[Target]struct{}
}

func (t *TargetSet) Add(target Target) {
	t.set[target] = struct{}{}
}

func (t *TargetSet) Remove(target Target) {
	delete(t.set, target)
}

func (t *TargetSet) Contains(target Target) bool {
	_, ok := t.set[target]
	return ok
}

type TargetBackend struct {
	mu sync.Mutex
	// Maps beacon row id to targets
	beaconTargetAssoc map[int64]*Target
	TargetSet
}

func NewTargetBackend() (*TargetBackend, error) {
	return &TargetBackend{
		beaconTargetAssoc: make(map[int64]*Target),
	}, nil
}

func (t *TargetBackend) AssociateBeacon(beaconID int64, target Target) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.beaconTargetAssoc[beaconID] = &target
}
