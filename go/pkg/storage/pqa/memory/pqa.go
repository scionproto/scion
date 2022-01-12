package memory

import (
	"context"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing/mechanisms/pqa"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
)

type PqaMemoryBackend struct {
	*Beacons
	Targets *TargetBackend
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

// Returns target originating from a given IA
func (b *PqaMemoryBackend) GetActiveTargets(ctx context.Context, src addr.IA) ([]pqa.Target, error) {
	b.Targets.mu.Lock()
	defer b.Targets.mu.Unlock()

	var targets []pqa.Target
	for target := range b.Targets.set {
		if target.ISD == src.I && target.AS == src.A {
			//targets = append(targets, pqa.TargetFromExtension(target))
		}
	}
	return targets, nil
}
