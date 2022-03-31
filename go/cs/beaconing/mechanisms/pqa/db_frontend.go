package pqa

import (
	"context"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
)

// Interface all backends need to implement
type DB interface {
	beacon.DB

	// Return all optimization targets for which the db has beacons for a given IA source
	GetActiveTargets(ctx context.Context, src addr.IA) ([]Target, error)
	// Returns the N best (N global constant in pqa.go) beacons for a given optimization tartget,
	// leading through some given intfs, and ignoring beacons that would loop if send to a given IA
	GetNBestsForGroup(ctx context.Context, src addr.IA, target Target, ingresIntfs []*ifstate.Interface, excludeLooping addr.IA) ([]*beacon.Beacon, error)
}
