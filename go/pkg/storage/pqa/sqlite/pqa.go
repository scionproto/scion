// Note: Package is discontinued in favor of ../memory, in the interest of time

package sqlite

import (
	"context"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	bcnsqlite "github.com/scionproto/scion/go/pkg/storage/beacon/sqlite"
)

type PqaSqlBackend struct {
	*bcnsqlite.Backend
	targetDB *TargetBackend
}

func New(path string, ia addr.IA) (*PqaSqlBackend, error) {
	beaconDB, err := bcnsqlite.New(path, ia)
	if err != nil {
		return nil, err
	}
	targetDB, err := NewTargetBackend("/home/sgyger/scion/gen/targets.db")
	if err != nil {
		return nil, err
	}

	return &PqaSqlBackend{
		Backend:  beaconDB,
		targetDB: targetDB,
	}, nil
}

// Close closes the database.
func (b *PqaSqlBackend) Close() error {
	var err error
	if err = b.targetDB.Close(); err != nil {
		return err
	}
	return b.Backend.Close()
}

func (e *PqaSqlBackend) InsertBeacon(
	ctx context.Context,
	b beacon.Beacon,
	usage beacon.Usage,
) (beacon.InsertStats, error) {

	// Store beacon in normal beacon storage
	stats, err := e.Backend.InsertBeacon(ctx, b, usage)
	if err != nil {
		return stats, err
	}

	logger := log.FromCtx(ctx)
	// If beacon has no pqaExtension, return
	pqaExtension0 := b.Segment.ASEntries[0].Extensions.PqaExtension
	if pqaExtension0 == nil {
		logger.Debug("Inserted beacon without extension.")
		return stats, nil
	}
	logger.Debug("Got beacon with extension")

	target := Target{
		Quality:    pqaExtension0.Quality,
		Direction:  pqaExtension0.Direction,
		Uniquifier: uint32(pqaExtension0.Uniquifier),
		ISD:        b.Segment.FirstIA().I,
		AS:         b.Segment.FirstIA().A,
	}
	if err := e.targetDB.AddTargetIfNotExists(ctx, target); err != nil {
		return stats, err
	}

	// Else add to storage
	return beacon.InsertStats{}, nil
}
