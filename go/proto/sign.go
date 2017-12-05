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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto"
)

var _ Cerealizable = (*SignS)(nil)

type SignS struct {
	Type      SignType
	Src       common.RawBytes
	Signature common.RawBytes
}

func NewSignS(type_ SignType, src common.RawBytes) *SignS {
	return &SignS{Type: type_, Src: src}
}

func (s *SignS) Copy() *SignS {
	return &SignS{
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
		return crypto.Sign(message, key, crypto.Ed25519)
	}
	return nil, common.NewCError("SignS.Sign: Unsupported SignType", "type", s.Type)
}

func (s *SignS) SignAndSet(key, message common.RawBytes) error {
	var err error
	s.Signature, err = s.Sign(key, message)
	return err
}

func (s *SignS) Verify(key, message common.RawBytes) error {
	switch s.Type {
	case SignType_none:
		return nil
	case SignType_ed25519:
		return crypto.Verify(message, s.Signature, key, crypto.Ed25519)
	}
	return common.NewCError("SignS.Verify: Unsupported SignType", "type", s.Type)
}

func (s *SignS) Pack() common.RawBytes {
	var raw common.RawBytes
	raw = append(raw, common.RawBytes(s.Type.String())...)
	raw = append(raw, s.Src...)
	raw = append(raw, s.Signature...)
	return raw
}

func (s *SignS) ProtoId() ProtoIdType {
	return Sign_TypeID
}

func (s *SignS) String() string {
	return fmt.Sprintf("SignType: %s SignSrc: %s Signature: %s", s.Type, s.Src, s.Signature)
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
