package memory

import (
	"context"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing/mechanisms/pqa"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
)

type PqaMemoryBackend struct {
	*Beacons
	*Targets
}

func New(path string, ia addr.IA) (*PqaMemoryBackend, error) {
	beaconDB, err := NewBeaconBackend(path, ia)
	if err != nil {
		return nil, err
	}
	targetDB, err := NewTargetBackend()
	if err != nil {
		return nil, err
	}

	return &PqaMemoryBackend{
		Beacons: beaconDB,
		Targets: targetDB,
	}, nil
}

func (b *PqaMemoryBackend) InsertBeacon(
	ctx context.Context,
	bcn beacon.Beacon,
	usage beacon.Usage,
) (beacon.InsertStats, error) {

	// Store beacon in normal beacon storage
	stats, err := b.Beacons.InsertBeacon(ctx, bcn, usage)
	if err != nil {
		return stats, err
	}

	logger := log.FromCtx(ctx)
	// If beacon has no pqaExtension, return
	pqaExtension0 := bcn.Segment.ASEntries[0].Extensions.PqaExtension
	if pqaExtension0 == nil {
		logger.Debug("Inserted beacon without extension.")
		return stats, nil
	}
	logger.Debug("Got beacon with extension")

	target := pqa.Target{
		Quality:    pqaExtension0.Quality,
		Direction:  pqaExtension0.Direction,
		Uniquifier: uint32(pqaExtension0.Uniquifier),
		ISD:        bcn.Segment.FirstIA().I,
		AS:         bcn.Segment.FirstIA().A,
	}

	if b.Targets.Contains(target) {
		logger.Debug("Target already in set")
	} else {
		logger.Debug("Adding target to set")
		b.Targets.Add(target)
	}

	beaconID, err := b.Beacons.getBeaconID(ctx, bcn)
	if err != nil {
		return stats, err
	}

	b.Targets.AssociateBeacon(beaconID, target)
	return beacon.InsertStats{}, nil
}

func (b *PqaMemoryBackend) GetNBestsForGroup(
	ctx context.Context,
	src addr.IA,
	target pqa.Target,
	ingresIntfs []*ifstate.Interface,
	excludeLooping addr.IA,
) ([]beacon.Beacon, error) {
	b.Targets.mu.Lock()
	defer b.Targets.mu.Unlock()

	// Get beaconIds that are associated with the target
	bcnIds := b.Targets.GetBeaconIdsForTarget(ctx, target)
	if len(bcnIds) == 0 {
		return nil, nil
	}

	// Get beacons from beacon ids
	bcnCandidates := make([]beacon.Beacon, 0, len(bcnIds))
	for _, bcnId := range bcnIds {
		bcn, err := b.Beacons.GetBeaconById(ctx, bcnId)
		if err != nil {
			return nil, err
		}
		bcnCandidates = append(bcnCandidates, *bcn)
	}

	// Filter is a predicate on beacons
	type BeaconFilter func(beacon.Beacon) bool
	applyFilter := func(bcns []beacon.Beacon, filter BeaconFilter) []beacon.Beacon {
		var filtered []beacon.Beacon
		for _, bcn := range bcns {
			if filter(bcn) {
				filtered = append(filtered, bcn)
			}
		}
		return filtered
	}

	// Filter out beacons that are not in the ingress interface set
	bcnCandidates = applyFilter(bcnCandidates, func(bcn beacon.Beacon) bool {
		for _, ingressIntf := range ingresIntfs {
			ingressIfid := ingressIntf.TopoInfo().ID
			if ingressIfid == bcn.InIfId {
				return true
			}
		}
		return false
	})

	// Filter beacons that would create a loop
	bcnCandidates = applyFilter(bcnCandidates, func(bcn beacon.Beacon) bool {
		if err := beacon.FilterLoop(bcn, excludeLooping, false); err != nil {
			return false
		}
		return true
	})

	if len(bcnCandidates) > pqa.N {
		bcnCandidates = bcnCandidates[:pqa.N]
	}
	return bcnCandidates, nil
}
