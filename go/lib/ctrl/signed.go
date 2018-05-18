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
	"fmt"

	"github.com/scionproto/scion/go/lib/assert"
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

func newSignedPld(cpld *Pld, sign *proto.SignS, key common.RawBytes) (*SignedPld, error) {
	// Make a copy of signer, so the caller can re-use it.
	spld := &SignedPld{Sign: sign.Copy()}
	if spld.Sign == nil && assert.On {
		assert.Must(len(key) == 0, "If there's no Sign, key must be empty")
	}
	if err := spld.SetPld(cpld); err != nil {
		return nil, err
	}
	if spld.Sign != nil {
		if err := spld.Sign.SignAndSet(key, spld.Blob); err != nil {
			return nil, err
		}
	}
	return spld, nil
}

func NewSignedPldFromRaw(b common.RawBytes) (*SignedPld, error) {
	sp := &SignedPld{}
	if len(b) < 4 {
		return nil, common.NewBasicError("Ctrl payload length field too short", nil,
			"minimum", 4, "actual", len(b))
	}
	n := common.Order.Uint32(b)
	if int(n)+4 != len(b) {
		return nil, common.NewBasicError("Invalid ctrl payload length", nil,
			"expected", n+4, "actual", len(b))
	}
	return sp, proto.ParseFromRaw(sp, sp.ProtoId(), b[4:])
}

func (sp *SignedPld) Pld() (*Pld, error) {
	var err error
	if sp.pld == nil {
		sp.pld, err = NewPldFromRaw(sp.Blob)
	}
	return sp.pld, err
}

func (sp *SignedPld) SetPld(p *Pld) error {
	var err error
	sp.pld = nil
	sp.Blob, err = proto.PackRoot(p)
	return err
}

func (sp *SignedPld) Len() int {
	return -1
}

func (sp *SignedPld) Copy() (common.Payload, error) {
	return &SignedPld{Blob: append(common.RawBytes(nil), sp.Blob...), Sign: sp.Sign.Copy()}, nil
}

func (sp *SignedPld) WritePld(b common.RawBytes) (int, error) {
	n, err := proto.WriteRoot(sp, b[4:])
	common.Order.PutUint32(b, uint32(n))
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
	common.Order.PutUint32(full, uint32(len(b)))
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
