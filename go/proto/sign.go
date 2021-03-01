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
	"encoding/binary"
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

var _ Cerealizable = (*SignS)(nil)

type SignS struct {
	Timestamp uint32
	// Type indicates the signature algorithm
	//
	// Deprecated: This is redundant information and only exists for historic
	// reasons. Signautres based on X.509 should neither set nor read this
	// value.
	Type SignType
	// Src holds the required metadata to verify the signature. The format is "STRING: METADATA".
	// The prefix consists of "STRING: " and is required to match the regex "^\w+\: ".
	// There are no format restrictions on the metadata.
	Src       []byte
	Signature []byte
}

func NewSignS(type_ SignType, src []byte) *SignS {
	return &SignS{Type: type_, Src: src}
}

func (s *SignS) Copy() *SignS {
	if s == nil {
		return nil
	}
	return &SignS{
		Timestamp: s.Timestamp,
		Type:      s.Type,
		Src:       append([]byte(nil), s.Src...),
		Signature: append([]byte(nil), s.Signature...),
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
func (s *SignS) Pack() []byte {
	return s.pack(nil, true)
}

// SigInput serializes the signature metadata to the signature input
// including the provided message. If setTimestamp is set, the timestamp of
// the signature metadata is updated to the current time, before creating
// the signature input. It should be true when signing to provide a recent
// timestamp. When verifying, it should be false to guarantee the same
// produced input.
func (s *SignS) SigInput(msg []byte, setTimestamp bool) []byte {
	if setTimestamp {
		s.SetTimestamp(time.Now())
	}
	return s.pack(msg, false)
}

// pack appends the type, src, signature (if needed) and timestamp fields to msg
func (s *SignS) pack(msg []byte, inclSig bool) []byte {
	msg = append([]byte(nil), msg...)
	msg = append(msg, []byte(s.Type.String())...)
	msg = append(msg, s.Src...)
	if inclSig {
		msg = append(msg, s.Signature...)
	}
	t := make([]byte, 4)
	binary.BigEndian.PutUint32(t, s.Timestamp)
	return append(msg, t...)
}

func (s *SignS) ProtoId() ProtoIdType {
	return Sign_TypeID
}

func (s *SignS) String() string {
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("SignType: %s Timestamp: %s SignSrc: %s Signature: %s", s.Type,
		util.TimeToString(s.Time()), s.Src, s.Signature)
}

var _ Cerealizable = (*SignedBlobS)(nil)

type SignedBlobS struct {
	Blob []byte
	Sign *SignS
}

func (sbs *SignedBlobS) Pack() []byte {
	var raw []byte
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
