// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

// This file contains the Go representation of a revocation info.

package path_mgmt

import (
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt/proto"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/segment/iface"
)

const MinRevTTL = 10 * time.Second // MinRevTTL is the minimum lifetime of a revocation

type RevTimeError string

func NewRevTimeError(r *RevInfo) RevTimeError {
	return RevTimeError(fmt.Sprintf(
		"Revocation is expired, timestamp: %s, TTL %s.",
		util.TimeToCompact(r.Timestamp()), r.TTL()))
}

func (ee RevTimeError) Timeout() bool {
	return true
}

func (ee RevTimeError) Error() string {
	return string(ee)
}

type RevInfo struct {
	IfID     iface.ID
	RawIsdas addr.IA
	// LinkType of revocation
	LinkType proto.LinkType
	// RawTimestamp the issuing timestamp in seconds.
	RawTimestamp uint32
	// RawTTL validity period of the revocation in seconds
	RawTTL uint32
}

func (r *RevInfo) IA() addr.IA {
	return r.RawIsdas
}

// Timestamp returns the issuing time stamp of the revocation.
func (r *RevInfo) Timestamp() time.Time {
	return util.SecsToTime(r.RawTimestamp)
}

func (r *RevInfo) TTL() time.Duration {
	return time.Duration(r.RawTTL) * time.Second
}

func (r *RevInfo) Expiration() time.Time {
	return r.Timestamp().Add(r.TTL())
}

func (r *RevInfo) Active() error {
	if r.TTL() < MinRevTTL {
		return serrors.New("Revocation TTL smaller than MinRevTTL.",
			"TTL", r.TTL().Seconds(), "MinRevTTL", MinRevTTL.Seconds())
	}
	now := time.Now()
	// Revocation is not valid if timestamp is not within the TTL window
	if r.Expiration().Before(now) {
		return NewRevTimeError(r)
	}
	if r.Timestamp().After(now.Add(time.Second)) {
		return serrors.New("Revocation timestamp is in the future.",
			"timestamp", util.TimeToCompact(r.Timestamp()))
	}
	return nil
}

func (r *RevInfo) String() string {
	return fmt.Sprintf("IA: %s IfID: %d Link type: %s Timestamp: %s TTL: %s", r.IA(), r.IfID,
		r.LinkType, util.TimeToCompact(r.Timestamp()), r.TTL())
}

// RelativeTTL returns the duration r is still valid for, relative to
// reference. If the revocation is already expired, the returned value is 0.
func (r *RevInfo) RelativeTTL(reference time.Time) time.Duration {
	expiration := r.Expiration()
	if expiration.Before(reference) {
		return 0
	}
	return expiration.Sub(reference)
}

func (r *RevInfo) Equal(other *RevInfo) bool {
	if r == nil || other == nil {
		return r == other
	}
	return r.SameIntf(other) &&
		r.RawTimestamp == other.RawTimestamp &&
		r.RawTTL == other.RawTTL
}

// SameIntf returns true if r and other both apply to the same interface.
func (r *RevInfo) SameIntf(other *RevInfo) bool {
	return r.IfID == other.IfID &&
		r.RawIsdas == other.RawIsdas &&
		r.LinkType == other.LinkType
}
