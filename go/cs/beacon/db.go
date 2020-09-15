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
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

const (
	// ErrReadingRows is the error message in case we fail to read more from
	// the database.
	ErrReadingRows common.ErrMsg = "Failed to read rows"
	// ErrParse is the error message in case the parsing a db entry fails.
	ErrParse common.ErrMsg = "Failed to parse entry"
)

// DBRead defines all read operations of the beacon DB.
type DBRead interface {
	// CandidateBeacons returns up to setSize beacons that are allowed for the
	// given usage. The result channel either carries beacons or errors. The
	// beacons in the channel are ordered by segment length from shortest to
	// longest. The channel must be drained, since the db might spawn go routines
	// to fill the channel.
	CandidateBeacons(ctx context.Context, setSize int, usage Usage, src addr.IA) (
		<-chan BeaconOrErr, error)
	// BeaconSources returns all source ISD-AS of the beacons in the database.
	BeaconSources(ctx context.Context) ([]addr.IA, error)
	// AllRevocations returns all revocations in the database as a channel. The
	// result channel either carries revocations or errors. The error can
	// either be ErrReadingRows or ErrParse. After a ErrReadingRows occurs the
	// channel is closed and the result might be incomplete. The channel must
	// be drained, since the implementation might spawn go routines to fill the
	// channel.
	AllRevocations(ctx context.Context) (<-chan RevocationOrErr, error)
}

// InsertStats provides statistics about an insertion.
type InsertStats struct {
	Inserted, Updated, Filtered int
}

// DBWrite defines all write operations of the beacon DB.
type DBWrite interface {
	InsertBeacon(ctx context.Context, beacon Beacon, usage Usage) (InsertStats, error)
	DeleteExpiredBeacons(ctx context.Context, now time.Time) (int, error)
	DeleteRevokedBeacons(ctx context.Context, now time.Time) (int, error)
	InsertRevocation(ctx context.Context, revocation *path_mgmt.SignedRevInfo) error
	DeleteRevocation(ctx context.Context, ia addr.IA, ifid common.IFIDType) error
	DeleteExpiredRevocations(ctx context.Context, now time.Time) (int, error)
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

// None indicates whether the beacons is not allowed to be used anywhere.
func (u Usage) None() bool {
	return u&0x0F == 0
}

func (u Usage) String() string {
	names := []string{}
	if u&UsageUpReg != 0 {
		names = append(names, "UpRegistration")
	}
	if u&UsageDownReg != 0 {
		names = append(names, "DownRegistration")
	}
	if u&UsageCoreReg != 0 {
		names = append(names, "CoreRegistration")
	}
	if u&UsageProp != 0 {
		names = append(names, "Propagation")
	}
	return fmt.Sprintf("Usage: [%s]", strings.Join(names, ","))
}

// PackBeacon packs a beacon.
func PackBeacon(ps *seg.PathSegment) ([]byte, error) {
	return proto.Marshal(seg.PathSegmentToPB(ps))
}

// UnpackBeacon unpacks a beacon.
func UnpackBeacon(raw []byte) (*seg.PathSegment, error) {
	var pb cppb.PathSegment
	if err := proto.Unmarshal(raw, &pb); err != nil {
		return nil, err
	}
	return seg.BeaconFromPB(&pb)
}
