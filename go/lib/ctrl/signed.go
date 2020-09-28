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

package ctrl

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

const LenSize = 4

var _ common.Payload = (*SignedPld)(nil)
var _ proto.Cerealizable = (*SignedPld)(nil)

type SignedPld struct {
	Blob common.RawBytes
	Sign *proto.SignS
	pld  *Pld
}

func newSignedPld(ctx context.Context, cpld *Pld, signer Signer) (*SignedPld, error) {
	// Make a copy of signer, so the caller can re-use it.
	var err error
	spld := &SignedPld{}
	if spld.Blob, err = proto.PackRoot(cpld); err != nil {
		return nil, err
	}
	sign, err := signer.SignLegacy(ctx, spld.Blob)
	if err != nil {
		return nil, err
	}
	spld.Sign = sign
	return spld, nil
}

func NewSignedPldFromRaw(b common.RawBytes) (*SignedPld, error) {
	sp := &SignedPld{}
	if len(b) < 4 {
		return nil, common.NewBasicError("Ctrl payload length field too short", nil,
			"minimum", 4, "actual", len(b))
	}
	n := binary.BigEndian.Uint32(b)
	if int(n)+4 != len(b) {
		return nil, common.NewBasicError("Invalid ctrl payload length", nil,
			"expected", n+4, "actual", len(b))
	}
	return sp, proto.ParseFromRaw(sp, b[4:])
}

// UnsafePld extracts the control payload without verifying the payload.
func (sp *SignedPld) UnsafePld() (*Pld, error) {
	var err error
	if sp.pld == nil {
		sp.pld, err = NewPldFromRaw(sp.Blob)
	}
	return sp.pld, err
}

// GetVerifiedPld extracts the control payload and verifies it. If
// verification fails, an error is returned instead.
func (sp *SignedPld) GetVerifiedPld(ctx context.Context, verifier Verifier) (*Pld, error) {
	return verifier.VerifyPld(ctx, sp)
}

func (sp *SignedPld) Len() int {
	return -1
}

func (sp *SignedPld) Copy() (common.Payload, error) {
	return &SignedPld{Blob: append(common.RawBytes(nil), sp.Blob...), Sign: sp.Sign.Copy()}, nil
}

func (sp *SignedPld) WritePld(b common.RawBytes) (int, error) {
	n, err := proto.WriteRoot(sp, b[4:])
	binary.BigEndian.PutUint32(b, uint32(n))
	return n + 4, err
}

func (sp *SignedPld) PackPld() (common.RawBytes, error) {
	b, err := proto.PackRoot(sp)
	if err != nil {
		return nil, err
	}
	// Make a larger buffer, to allow pre-pending of the length field.
	full := make(common.RawBytes, LenSize+len(b))
	// Write length field
	binary.BigEndian.PutUint32(full, uint32(len(b)))
	// Copy the encoded proto into the full buffer
	copy(full[LenSize:], b)
	return full, err
}

func (sp *SignedPld) ProtoId() proto.ProtoIdType {
	return proto.SignedCtrlPld_TypeID
}

func (sp *SignedPld) String() string {
	return fmt.Sprintf("SignedCtrlPld: %s %s", sp.Blob, sp.Sign)
}
