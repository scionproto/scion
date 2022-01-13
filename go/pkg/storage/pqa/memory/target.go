package memory

import (
	"context"
	"sync"

	"github.com/scionproto/scion/go/cs/beaconing/mechanisms/pqa"
	"github.com/scionproto/scion/go/lib/addr"
)

type TargetSet struct {
	set map[pqa.Target]struct{}
}

func NewTargetSet() *TargetSet {
	return &TargetSet{
		set: make(map[pqa.Target]struct{}),
	}
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

func (t *TargetSet) Slice() []pqa.Target {
	res := make([]pqa.Target, 0, len(t.set))
	for target := range t.set {
		res = append(res, target)
	}
	return res
}

type TargetPredicate func(pqa.Target) bool

func (t *TargetSet) Filter(pred TargetPredicate) *TargetSet {
	res := NewTargetSet()
	for target := range t.set {
		if pred(target) {
			res.Add(target)
		}
	}
	return res
}

type Targets struct {
	mu sync.Mutex
	// Maps beacon row id to targets
	beaconTargetAssoc  map[int64]*pqa.Target
	targetBeaconsAssoc map[pqa.Target][]int64
	TargetSet
}

func NewTargetBackend() (*Targets, error) {
	return &Targets{
		beaconTargetAssoc:  make(map[int64]*pqa.Target),
		targetBeaconsAssoc: make(map[pqa.Target][]int64),
		TargetSet:          *NewTargetSet(),
	}, nil
}

func (t *Targets) AssociateBeacon(beaconID int64, target pqa.Target) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.beaconTargetAssoc[beaconID] = &target

	targets, ok := t.targetBeaconsAssoc[target]
	if !ok {
		targets = make([]int64, 0)
	}
	targets = append(targets, beaconID)
	t.targetBeaconsAssoc[target] = targets
}

func (t *Targets) GetActiveTargets(ctx context.Context, src addr.IA) ([]pqa.Target, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.Filter(func(target pqa.Target) bool {
		return target.ISD == src.I && target.AS == src.A
	}).Slice(), nil
}

func (t *Targets) GetBeaconIdsForTarget(ctx context.Context, target pqa.Target) []int64 {
	return t.targetBeaconsAssoc[target]
}
