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
	"context"
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
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

var _ proto.Cerealizable = (*RevInfo)(nil)

type RevInfo struct {
	IfID     common.IFIDType
	RawIsdas addr.IAInt `capnp:"isdas"`
	// LinkType of revocation
	LinkType proto.LinkType
	// RawTimestamp the issuing timestamp in seconds.
	RawTimestamp uint32 `capnp:"timestamp"`
	// RawTTL validity period of the revocation in seconds
	RawTTL uint32 `capnp:"ttl"`
}

func NewRevInfoFromRaw(b []byte) (*RevInfo, error) {
	r := &RevInfo{}
	return r, proto.ParseFromRaw(r, b)
}

func (r *RevInfo) IA() addr.IA {
	return r.RawIsdas.IA()
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

func (r *RevInfo) ProtoId() proto.ProtoIdType {
	return proto.RevInfo_TypeID
}

func (r *RevInfo) Pack() ([]byte, error) {
	return proto.PackRoot(r)
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

// Verifier is used to verify signatures.
type Verifier interface {
	// Verify verifies the packed signed revocation based on the signature meta
	// data.
	Verify(ctx context.Context, msg []byte, sign *proto.SignS) error
}

var _ proto.Cerealizable = (*SignedRevInfo)(nil)

type SignedRevInfo struct {
	Blob    []byte
	Sign    *proto.SignS
	revInfo *RevInfo `capnp:"-"`
}

func NewSignedRevInfoFromRaw(b []byte) (*SignedRevInfo, error) {
	sr := &SignedRevInfo{}
	return sr, proto.ParseFromRaw(sr, b)
}

func NewSignedRevInfo(r *RevInfo) (*SignedRevInfo, error) {
	rawR, err := r.Pack()
	if err != nil {
		return nil, err
	}
	return &SignedRevInfo{
		Blob:    rawR,
		Sign:    &proto.SignS{},
		revInfo: r,
	}, nil
}

func (sr *SignedRevInfo) ProtoId() proto.ProtoIdType {
	return proto.SignedBlob_TypeID
}

func (sr *SignedRevInfo) RevInfo() (*RevInfo, error) {
	var err error
	if sr.revInfo == nil {
		sr.revInfo, err = NewRevInfoFromRaw(sr.Blob)
	}
	return sr.revInfo, err
}

func (sr *SignedRevInfo) Pack() ([]byte, error) {
	return proto.PackRoot(sr)
}

func (sr *SignedRevInfo) String() string {
	revInfo, err := sr.RevInfo()
	if err != nil {
		return fmt.Sprintf("SignedRevInfo: Error parsing RevInfo, Blob: %s Sign: %s", err, sr.Sign)
	}
	return fmt.Sprintf("SignedRevInfo: RevInfo: %s Sign: %s", revInfo, sr.Sign)
}
