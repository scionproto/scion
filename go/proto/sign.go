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
	"github.com/scionproto/scion/go/lib/serrors"
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

// Valid reports whether the signature is valid.
func (s *SignS) Valid(threshold time.Duration) error {
	if s == nil {
		return serrors.New("signature is unset")
	}
	if len(s.Signature) == 0 {
		return serrors.New("missing signature", "type", s.Type)
	}
	if time.Now().Add(threshold).Before(s.Time()) {
		return serrors.New("invalid timestamp, signature from future")
	}
	return nil
}

// SetTimestamp sets the timestamp.
func (s *SignS) SetTimestamp(ts time.Time) {
	s.Timestamp = util.TimeToSecs(ts)
}

// Time returns the timestamp. If the receiver is nil, the zero value is returned.
func (s *SignS) Time() time.Time {
	if s != nil {
		return util.SecsToTime(s.Timestamp)
	}
	return time.Time{}
}

// Pack serializes the signature metadata including the signature.
func (s *SignS) Pack() common.RawBytes {
	return s.pack(nil, true)
}

// SigInput serializes the signature metadata to the signature input
// including the provided message. If setTimestamp is set, the timestamp of
// the signature metadata is updated to the current time, before creating
// the signature input. It should be true when signing to provide a recent
// timestamp. When verifying, it should be false to guarantee the same
// produced input.
func (s *SignS) SigInput(msg common.RawBytes, setTimestamp bool) common.RawBytes {
	if setTimestamp {
		s.SetTimestamp(time.Now())
	}
	return s.pack(msg, false)
}

// pack appends the type, src, signature (if needed) and timestamp fields to msg
func (s *SignS) pack(msg common.RawBytes, inclSig bool) common.RawBytes {
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
