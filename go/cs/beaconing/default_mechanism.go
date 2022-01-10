package beaconing

import (
	"context"
	"hash"
	"math"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/serrors"
)

/* ----------------------------------------- */
// DefaultMechanismBase

// Selects beacons that are shortest i.t.o. hop count + one that is diverse
type DefaultMechanismBase struct {
	MechanismBase
	DB       beacon.DB
	usager   beacon.Usager
	Extender Extender
}

func NewDefaultMechanismBase(
	IA addr.IA,
	MTU uint16,
	Signer seg.Signer,
	Intfs *ifstate.Interfaces,
	MAC func() hash.Hash,
	MaxExpTime func() uint8,
	StaticInfo func() *StaticInfoCfg,

	db beacon.DB,
	base MechanismBase,
) *DefaultMechanismBase {
	ext := &DefaultExtender{
		IA:         IA,
		MTU:        MTU,
		Signer:     Signer,
		Intfs:      Intfs,
		MAC:        MAC,
		MaxExpTime: MaxExpTime,
		StaticInfo: StaticInfo,
	}
	return &DefaultMechanismBase{
		MechanismBase: base,
		DB:            db,
		Extender:      ext,
	}
}

// Creates a batch ready for propagation out of a set of selected beacons
// By fetching interfaces, peers, mapping interfaces to beacons,
// filtering beacons, deep copying beacons, and extending beacons with
// interfaces they should leave on
func (mech *DefaultMechanismBase) createBatch(ctx context.Context, beacons []beacon.Beacon) (SendableBeaconsBatch, error) {
	intfs := mech.getIntfsNeedingBeacons()
	peers := mech.GetPeers()

	batch := mech.createAllToAllBatch(peers, intfs, beacons)
	batch.FilterLooping(mech.AllowIsdLoop)
	batch.DeepCopyBeacons(ctx)

	if extErr := batch.ExtendBeacons(ctx, mech.Extender, peers); extErr != nil {
		return nil, serrors.WrapStr("error extending", extErr, "intf -> bcns:", batch)
	}
	return batch, nil
}

// Filters out beacons that have an ingress interface not part of mech.AllInterfaces
func (mech *DefaultMechanismBase) FilterInexistingIngressBeacons(beacons []beacon.Beacon) []beacon.Beacon {
	res := beacons[:0]
	for _, b := range beacons {
		if mech.AllInterfaces.Get(b.InIfId) == nil {
			continue
		}
		res = append(res, b)
	}
	return res
}

// creates a new SendableBeaconsBatch with all interfaces mapping to all beacons
func (p *DefaultMechanismBase) createAllToAllBatch(peers []uint16, intfs []*ifstate.Interface, bcns []beacon.Beacon) SendableBeaconsBatch {
	res := make(SendableBeaconsBatch)
	for _, intf := range intfs {
		res[intf] = append(res[intf], bcns...)
	}
	return res
}

// SelectBeacons implements a very simple selection algorithm. The best beacon
// is the one with a shortest path. The slice contains the k-1 shortest
// beacons. The last beacon is either the most diverse beacon from the remaining
// beacons, if the diversity exceeds what has already been served. Or the
// shortest remaining beacon, otherwise.
func (m DefaultMechanismBase) selectBeacons(beacons []beacon.Beacon, resultSize int) []beacon.Beacon {
	if len(beacons) <= resultSize {
		return beacons
	}

	result := make([]beacon.Beacon, resultSize-1, resultSize)
	copy(result, beacons[:resultSize-1])
	_, diversity := m.selectMostDiverse(result, result[0])

	// Check if we find a more diverse beacon in the rest.
	mostDiverseRest, diversityRest := m.selectMostDiverse(beacons[resultSize-1:], result[0])
	if diversityRest > diversity {
		return append(result, mostDiverseRest)
	}
	// If the most diverse beacon was already served, serve shortest from the
	// rest.
	return append(result, beacons[resultSize-1])
}

// selectMostDiverse selects the most diverse beacon compared to the provided best beacon from all
// provided beacons and returns it and its diversity.
func (DefaultMechanismBase) selectMostDiverse(beacons []beacon.Beacon, best beacon.Beacon) (beacon.Beacon, int) {
	if len(beacons) == 0 {
		return beacon.Beacon{}, -1
	}

	maxDiversity := -1
	minLen := math.MaxUint16
	var diverse beacon.Beacon
	for _, b := range beacons {
		diversity := best.Diversity(b)
		l := len(b.Segment.ASEntries)

		if diversity > maxDiversity || (diversity == maxDiversity && minLen > l) {
			diverse, minLen, maxDiversity = b, l, diversity
		}
	}
	return diverse, maxDiversity
}

/* ----------------------------------------- */
// DefaultMechanismNonCore

type DefaultMechanismNonCore struct {
	DefaultMechanismBase
	Policies beacon.Policies
}

func NewDefaultMechanismNonCore(
	db beacon.DB,
	policies beacon.Policies,
	IA addr.IA,
	AllInterfaces *ifstate.Interface,
) *DefaultMechanismNonCore {
	policies.InitDefaults()
	if err := policies.Validate(); err != nil {
		return nil
	}
	return &DefaultMechanismNonCore{
		Policies: policies,
	}
}

func (mech *DefaultMechanismNonCore) ProvidePropagationBatch(ctx context.Context, tick Tick) (SendableBeaconsBatch, error) {
	mech.Tick = tick
	policy := mech.Policies.Prop
	beacons, err := mech.DB.CandidateBeacons(ctx, policy.CandidateSetSize,
		beacon.UsageFromPolicyType(policy.Type), addr.IA{})
	if err != nil {
		return nil, err
	}

	beacons = mech.selectBeacons(beacons, policy.BestSetSize)
	beacons = mech.FilterInexistingIngressBeacons(beacons)

	batch, batchErr := mech.createBatch(ctx, beacons)
	if batchErr != nil {
		return nil, err
	}

	return batch, nil

}

/* ----------------------------------------- */
// DefaultMechanismCore
type DefaultMechanismCore struct {
	DefaultMechanismBase
	Policies beacon.CorePolicies
}

func NewDefaultMechanismCore(policies beacon.CorePolicies, db beacon.DB) (*DefaultMechanismCore, error) {
	policies.InitDefaults()
	if err := policies.Validate(); err != nil {
		return nil, err
	}
	mech := &DefaultMechanismCore{
		Policies: policies,
	}
	return mech, nil
}

func (mech *DefaultMechanismCore) ProvidePropagationBatch(ctx context.Context, tick Tick) (SendableBeaconsBatch, error) {
	mech.Tick = tick
	policy := mech.Policies.Prop
	srcs, srcErr := mech.DB.BeaconSources(ctx)
	if srcErr != nil {
		return nil, srcErr
	}
	var beacons []beacon.Beacon
	for _, src := range srcs {
		candidate_bcns, err := mech.DB.CandidateBeacons(ctx, policy.CandidateSetSize,
			beacon.UsageFromPolicyType(policy.Type), src)
		if err != nil {
			return nil, err
		}

		candidate_bcns = mech.selectBeacons(candidate_bcns, policy.BestSetSize)
		candidate_bcns = mech.FilterInexistingIngressBeacons(candidate_bcns)
		beacons = append(beacons, candidate_bcns...)
	}

	batch, batchErr := mech.createBatch(ctx, beacons)
	if batchErr != nil {
		return nil, batchErr
	}
	return batch, nil

}
