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
	"fmt"
	"io"
	"strings"

	"github.com/scionproto/scion/go/lib/infra/modules/db"
)

// DBRead defines all read operations of the beacon DB.
type DBRead interface {
	// CandidateBeacons returns up to setSize beacons that are allowed for
	// the given usage. The result channel either carries beacons or
	// errors. After sending the first error, the channel is closed. The
	// channel must be drained, since the db might spawn go routines to
	// fill the channel.
	CandidateBeacons(ctx context.Context, setSize int, usage Usage) (
		<-chan BeaconOrErr, error)
}

// DBWrite defines all write operations of the beacon DB.
type DBWrite interface {
	InsertBeacon(ctx context.Context, beacon Beacon, usage Usage) (int, error)
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
	db.LimitSetter
	io.Closer
}

const (
	// UsageUpReg indicates the beacon is allowed to be registered as an up segment.
	UsageUpReg Usage = 0x01
	// UsageDownReg indicates the beacon is allowed to be registered as a down segment.
	UsageDownReg Usage = 0x02
	// UsageCoreReg indicates the beacon is allowed to be registered as a core segment.
	UsageCoreReg Usage = 0x04
	// UsageProp indicates the beacon is allowed to be propagated.
	UsageProp Usage = 0x08
)

// Usage indicates what the beacon is allowed to be used for according to the policies.
type Usage int

// UsageFromPolicyType maps the policy type to the usage flag.
func UsageFromPolicyType(policyType PolicyType) Usage {
	switch policyType {
	case UpRegPolicy:
		return UsageUpReg
	case DownRegPolicy:
		return UsageDownReg
	case CoreRegPolicy:
		return UsageCoreReg
	case PropPolicy:
		return UsageProp
	default:
		panic(fmt.Sprintf("Invalid policyType: %v", policyType))
	}
}

func (u Usage) String() string {
	names := []string{}
	if u&UsageUpReg != 0 {
		names = append(names, "UpRegistration")
	}
	if u&UsageDownReg != 0 {
		names = append(names, "UpRegistration")
	}
	if u&UsageCoreReg != 0 {
		names = append(names, "UpRegistration")
	}
	if u&UsageProp != 0 {
		names = append(names, "UpRegistration")
	}
	return fmt.Sprintf("Usage: [%s]", strings.Join(names, ","))
}
