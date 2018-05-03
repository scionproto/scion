// Copyright 2017 ETH Zurich
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

	//log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

const MinRevTTL = 10 * time.Second // MinRevTTL is the minimum lifetime of a revocation

var _ common.Timeout = (*RevTimeError)(nil)

type RevTimeError string

func NewRevTimeError(ts uint64, ttl uint32) RevTimeError {
	return RevTimeError(fmt.Sprintf(
		"Revocation is expired, timestamp: %s, TTL %ds.",
		util.TimeToString(util.USecsToTime(ts)), ttl))
}

func (ee RevTimeError) Timeout() bool {
	return true
}

func (ee RevTimeError) Error() string {
	return string(ee)
}

var _ proto.Cerealizable = (*RevInfo)(nil)

type RevInfo struct {
	IfID     uint64
	RawIsdas addr.IAInt `capnp:"isdas"`
	// LinkType of revocation
	LinkType  proto.LinkType
	Timestamp uint64
	// TTL validity period of the revocation in seconds
	TTL uint32 `capnp:"ttl"`
}

func NewRevInfoFromRaw(b common.RawBytes) (*RevInfo, error) {
	r := &RevInfo{}
	return r, proto.ParseFromRaw(r, r.ProtoId(), b)
}

func (r *RevInfo) IA() addr.IA {
	return r.RawIsdas.IA()
}

func (r *RevInfo) Active() error {
	if r.TTL < uint32(MinRevTTL.Seconds()) {
		return common.NewBasicError("Revocation TTL smaller than MinRevTTL.", nil,
			"TTL", r.TTL, "MinRevTTL", MinRevTTL.Seconds())
	}
	now := uint64(time.Now().Unix())
	// Revocation is not valid if timestamp is not within the TTL window
	if r.Timestamp+uint64(r.TTL) < now {
		return NewRevTimeError(r.Timestamp, r.TTL)
	}
	if r.Timestamp > now+1 {
		return common.NewBasicError("Revocation timestamp is in the future.", nil,
			"timestamp", util.TimeToString(util.USecsToTime(r.Timestamp)))
	}
	return nil
}

func (r *RevInfo) ProtoId() proto.ProtoIdType {
	return proto.RevInfo_TypeID
}

func (r *RevInfo) String() string {
	return fmt.Sprintf("IA: %s IfID: %d Link type: %s Timestamp: %s TTL: %ds", r.IA(), r.IfID,
		r.LinkType, util.TimeToString(util.USecsToTime(uint64(r.Timestamp))), r.TTL)
}

var _ proto.Cerealizable = (*SignedRevInfo)(nil)

type SignedRevInfo struct {
	Blob    common.RawBytes
	Sign    *proto.SignS
	revInfo *RevInfo `capnp:"-"`
}

func NewSignedRevInfoFromRaw(b common.RawBytes) (*SignedRevInfo, error) {
	sr := &SignedRevInfo{}
	return sr, proto.ParseFromRaw(sr, sr.ProtoId(), b)
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

func (sp *SignedRevInfo) String() string {
	return fmt.Sprintf("SignedRevInfo: %s %s", sp.Blob, sp.Sign)
}
