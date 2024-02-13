// Copyright 2021 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package beacon defines interfaces that extend the capabilities of a beacon storage compared to
// the beacon.DB interface. These additional capabilities are used outside of the beacon package.
// For example, they are used by the service management API.
package beacon

import (
	"context"
	"time"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/pkg/addr"
)

// Cleanable is a database that needs periodic clean up of expired beacons.
type Cleanable interface {
	// DeleteExpiredBeacons removes all beacons that have an expiration time
	// before the passed time value.
	// The return value indicates the number of beacons that were removed.
	DeleteExpiredBeacons(ctx context.Context, now time.Time) (int, error)
}

type QueryParams struct {
	// SegIDs defines the list of segment IDs that beacons need to match at least one of.
	// If a specified segment ID is shorter than a full segment ID,
	// it is treated as prefix in the matching process.
	// Beacons are returned irrespective of their segment ID if SegIDs is empty.
	SegIDs [][]byte
	// StartsAt defines the list of ISD-AS IDs that beacons need to match at least one of.
	// Zero entries in any IA (ISD or AS or both) function as wildcards.
	// Beacons are returned irrespective of their start AS if StartsAt is empty.
	StartsAt []addr.IA
	// IngressInterfaces defines the list of ingress interface ids
	// that beacons need to batch at least one of.
	// Beacons are returned irrespective of their ingress interface if IngressInterfaces is empty.
	IngressInterfaces []uint16
	// Usage is the list of beacon usages that beacons need to match at least one of.
	// A usage matches if all it's set bits are also set in the beacon's usage.
	// Beacons are returned irrespective of their usage if Usages is empty.
	Usages []beacon.Usage
	// ValidAt specifies the time that beacons need to be valid at to be matched.
	// Beacons are returned irrespective of their validity if ValidAt is the zero time.
	ValidAt time.Time
}

type Beacon struct {
	Beacon      beacon.Beacon
	Usage       beacon.Usage
	LastUpdated time.Time
}

type BeaconAPI interface {
	// GetBeacons returns all beacons matching the parameters specified.
	GetBeacons(context.Context, *QueryParams) ([]Beacon, error)
	// DeleteBeacon removes all beacons that have the prefix of the specified segment ID.
	DeleteBeacon(ctx context.Context, partialID string) error
}
