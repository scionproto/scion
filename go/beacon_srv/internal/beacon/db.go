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

package beacon

import (
	"context"
	"database/sql"
	"io"
)

// DBRead defines all read operations of the beacon DB.
type DBRead interface {
	// CandidateBeacons returns up to setSize beacons that are allowed for
	// the given policy type. The result channel either carries beacons or
	// errors. After sending the first error, the channel is closed.
	CandidateBeacons(ctx context.Context, setSize int, policyType PolicyType) (
		<-chan BeaconOrErr, error)
}

// DBWrite defines all write operations of the beacon DB.
type DBWrite interface {
	InsertBeacon(ctx context.Context, beacon Beacon, allowed Allowed) (int, error)
}

// DBReadWrite defines all read an write operations of the beacon DB.
type DBReadWrite interface {
	DBRead
	DBWrite
}

// Transaction defines all operations of a transaction on the beacon DB.
type Transaction interface {
	DBReadWrite
	Commit() error
	Rollback() error
}

// DB defines the interface that all beacon DB backends have to implement.
type DB interface {
	DBReadWrite
	BeginTransaction(ctx context.Context, opts *sql.TxOptions) (Transaction, error)
	io.Closer
}

// Allowed indicates what the beacon is allowed to be used for according to the policies.
type Allowed struct {
	// UpReg indicates whether the beacon can be used for up-segment registration.
	UpReg bool
	// DownReg indicates whether the beacon can be used for down-segment registration.
	DownReg bool
	// CoreReg indicates whether the beacon can be used for core-segment registration.
	CoreReg bool
	// Prop indicates whether the beacon can be used for propagation.
	Prop bool
}
