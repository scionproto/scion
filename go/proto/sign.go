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

package proto

import (
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto"
	"github.com/scionproto/scion/go/lib/util"
)

var _ Cerealizable = (*SignS)(nil)

type SignS struct {
	Timestamp uint32
	Type      SignType
	// Src holds the required metadata to verify the signature. The format is "STRING: METADATA".
	// The prefix consists of "STRING: " and is required to match the regex "^\w+\: ".
	// There are no format restrictions on the metadata.
	Src       common.RawBytes
	Signature common.RawBytes
}

func NewSignS(type_ SignType, src common.RawBytes) *SignS {
	return &SignS{Type: type_, Src: src}
}

func (s *SignS) Copy() *SignS {
	if s == nil {
		return nil
	}
	return &SignS{
		Timestamp: s.Timestamp,
		Type:      s.Type,
		Src:       append(common.RawBytes(nil), s.Src...),
		Signature: append(common.RawBytes(nil), s.Signature...),
	}
}

func (s *SignS) Sign(key, message common.RawBytes) (common.RawBytes, error) {
	switch s.Type {
	case SignType_none:
		return nil, nil
	case SignType_ed25519:
		return crypto.Sign(s.sigPack(message, false), key, crypto.Ed25519)
	}
	return nil, common.NewBasicError("SignS.Sign: Unsupported SignType", nil, "type", s.Type)
}

func (s *SignS) SignAndSet(key, message common.RawBytes) error {
	var err error
	s.Timestamp = uint32(time.Now().Unix())
	s.Signature, err = s.Sign(key, message)
	return err
}

// Time returns the timestamp. If the receiver is nil, the zero value is returned.
func (s *SignS) Time() time.Time {
	if s != nil {
		return util.USecsToTime(s.Timestamp)
	}
	return time.Time{}
}

func (s *SignS) Verify(key, message common.RawBytes) error {
	switch s.Type {
	case SignType_none:
		return nil
	case SignType_ed25519:
		return crypto.Verify(s.sigPack(message, false), s.Signature, key, crypto.Ed25519)
	}
	return common.NewBasicError("SignS.Verify: Unsupported SignType", nil, "type", s.Type)
}

func (s *SignS) Pack() common.RawBytes {
	return s.sigPack(nil, true)
}

// sigPack appends the type, src, signature (if needed) and timestamp fields to msg
func (s *SignS) sigPack(msg common.RawBytes, inclSig bool) common.RawBytes {
	msg = append(common.RawBytes(nil), msg...)
	msg = append(msg, common.RawBytes(s.Type.String())...)
	msg = append(msg, s.Src...)
	if inclSig {
		msg = append(msg, s.Signature...)
	}
	t := make(common.RawBytes, 4)
	common.Order.PutUint32(t, s.Timestamp)
	return append(msg, t...)
}

func (s *SignS) ProtoId() ProtoIdType {
	return Sign_TypeID
}

func (s *SignS) String() string {
	return fmt.Sprintf("SignType: %s Timestamp: %s SignSrc: %s Signature: %s", s.Type,
		util.TimeToString(s.Time()), s.Src, s.Signature)
}

var _ Cerealizable = (*SignedBlobS)(nil)

type SignedBlobS struct {
	Blob common.RawBytes
	Sign *SignS
}

func (sbs *SignedBlobS) Pack() common.RawBytes {
	var raw common.RawBytes
	raw = append(raw, sbs.Blob...)
	raw = append(raw, sbs.Sign.Pack()...)
	return raw
}

func (sbs *SignedBlobS) ProtoId() ProtoIdType {
	return SignedBlob_TypeID
}

func (sbs *SignedBlobS) String() string {
	return fmt.Sprintf("Blob: %s Sign: %s", sbs.Blob[:20], sbs.Sign)
}
