// Copyright 2019 Anapaya Systems
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

package beaconstorage

import (
	"context"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra/modules/cleaner"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/proto"
)

// Store is the interface to interact with the beacon store.
type Store interface {
	// PreFilter indicates whether the beacon will be filtered on insert by
	// returning an error with the reason. This allows the caller to drop
	// ignored beacons.
	PreFilter(beacon beacon.Beacon) error
	// BeaconsToPropagate returns a channel that provides all beacons to
	// propagate at the time of the call. The selection is based on the
	// configured propagation policy.
	BeaconsToPropagate(ctx context.Context) (<-chan beacon.BeaconOrErr, error)
	// SegmentsToRegister returns a channel that provides all beacons to
	// register at the time of the call. The selections is based on the
	// configured propagation policy for the requested segment type.
	SegmentsToRegister(ctx context.Context, segType proto.PathSegType) (
		<-chan beacon.BeaconOrErr, error)
	// InsertBeacon adds a verified beacon to the store, ignoring revocations.
	InsertBeacon(ctx context.Context, beacon beacon.Beacon) (beacon.InsertStats, error)
	// InsertRevocations inserts the revocation into the BeaconDB.
	// The provided revocation must be verified by the caller.
	InsertRevocations(ctx context.Context, revocations ...*path_mgmt.SignedRevInfo) error
	// DeleteRevocation deletes the revocation from the BeaconDB.
	DeleteRevocation(ctx context.Context, ia addr.IA, ifid common.IFIDType) error
	// UpdatePolicy updates the policy. Beacons that are filtered by all
	// policies after the update are removed.
	UpdatePolicy(ctx context.Context, policy beacon.Policy) error
	// MaxExpTime returns the segment maximum expiration time for the given policy.
	MaxExpTime(policyType beacon.PolicyType) spath.ExpTimeType
	// DeleteExpired deletes expired Beacons from the store.
	DeleteExpiredBeacons(ctx context.Context) (int, error)
	// DeleteExpiredRevocations deletes expired Revocations from the store.
	DeleteExpiredRevocations(ctx context.Context) (int, error)
	// Close closes the store.
	Close() error
}

// NewBeaconCleaner creates a cleaner task, which deletes expired beacons.
func NewBeaconCleaner(s Store) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		return s.DeleteExpiredBeacons(ctx)
	}, "bs_beacon")
}

// NewRevocationCleaner creates a cleaner task, which deletes expired revocations.
func NewRevocationCleaner(s Store) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		return s.DeleteExpiredRevocations(ctx)
	}, "bs_revocation")
}
