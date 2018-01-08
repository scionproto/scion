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

//    HashTree:
//
//    0B       1        2        3        4        5        6        7
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    | xxxxxxxxxxxxxxxxxxxxxxxx |  0x05  | Height |reserved|      Order      |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                               Signature (8 lines)                     |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                               Hashes (height * 2)                     |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//

package scmp_auth

import (
	"bytes"
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spse"
)

var _ common.Extension = (*HashTreeExtn)(nil)

// HashTreeExtn is the implementation of the SCMPAuthHashTree extension.
// It is used to authenticate scmp messages.
type HashTreeExtn struct {
	*spse.BaseExtn
	// Height is the height of the hash tree. Max height is 16.
	Height uint8
	// Order is a bit vector. The bit at index i is associated with hash i.
	// 0 (1) indicates hash i shall be used as left (right) input.
	Order common.RawBytes
	// Signature is the signature of the root hash.
	Signature common.RawBytes
	// Hashes are the hashes to verify the proof.
	// At index 0 is the leaf hash. At index height is the root hash.
	Hashes common.RawBytes
}

const (
	MaxHeight = 16

	HeightLength    = 1
	ReservedLength  = 1
	OrderLength     = 2
	SignatureLength = 64
	HashLength      = 16

	HeightOffset    = spse.SecModeLength
	OrderOffset     = HeightOffset + ReservedLength + HeightLength
	SignatureOffset = OrderOffset + OrderLength
	HashesOffset    = SignatureOffset + SignatureLength
)

func NewHashTreeExtn(height uint8) (*HashTreeExtn, error) {
	if height > MaxHeight {
		return nil, common.NewBasicError("Invalid height", nil,
			"height", height, "max height", MaxHeight)
	}

	extn := &HashTreeExtn{BaseExtn: &spse.BaseExtn{SecMode: spse.ScmpAuthHashTree}}

	extn.Height = height
	extn.Order = make(common.RawBytes, OrderLength)
	extn.Signature = make(common.RawBytes, SignatureLength)
	extn.Hashes = make(common.RawBytes, int(height)*HashLength)
	return extn, nil
}

func (s HashTreeExtn) SetOrder(order common.RawBytes) error {
	if len(order) != OrderLength {
		return common.NewBasicError("Invalid order length", nil,
			"expected", OrderLength, "actual", len(order))
	}
	copy(s.Order, order)
	return nil

}

func (s HashTreeExtn) SetSignature(signature common.RawBytes) error {
	if len(signature) != SignatureLength {
		return common.NewBasicError("Invalid signature length", nil,
			"expected", SignatureLength, "actual", len(signature))
	}
	copy(s.Signature, signature)
	return nil

}

func (s HashTreeExtn) SetHashes(hashes common.RawBytes) error {
	if len(hashes) != len(s.Hashes) {
		return common.NewBasicError("Invalid hashes length", nil,
			"expected", len(s.Hashes), "actual", len(hashes))
	}
	copy(s.Hashes, hashes)
	return nil

}

func (s *HashTreeExtn) Write(b common.RawBytes) error {
	if len(b) < s.Len() {
		return common.NewBasicError("Buffer too short", nil,
			"method", "SCMPAuthHashTreeExtn.Write", "expected min", s.Len(), "actual", len(b))
	}
	b[0] = uint8(s.SecMode)
	b[HeightOffset] = s.Height
	copy(b[OrderOffset:SignatureOffset], s.Order)
	copy(b[SignatureOffset:HashesOffset], s.Signature)
	copy(b[HashesOffset:], s.Hashes)
	return nil
}

func (s *HashTreeExtn) Pack() (common.RawBytes, error) {
	b := make(common.RawBytes, s.Len())
	if err := s.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *HashTreeExtn) Copy() common.Extension {
	c, _ := NewHashTreeExtn(s.Height)
	copy(c.Order, s.Order)
	copy(c.Signature, s.Signature)
	copy(c.Hashes, s.Hashes)
	return c
}

func (s *HashTreeExtn) Len() int {
	return HashesOffset + len(s.Hashes)
}

func (s *HashTreeExtn) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "AuthHashTreeExtn (%dB): SecMode: %d\n", s.Len(), s.SecMode)
	fmt.Fprintf(buf, " Height: %x", s.Height)
	fmt.Fprintf(buf, " Order: %s", s.Order)
	fmt.Fprintf(buf, " Signature: %s", s.Signature)
	fmt.Fprintf(buf, " Hashes: %s", s.Hashes)
	return buf.String()
}
