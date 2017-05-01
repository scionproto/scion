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
//    | xxxxxxxxxxxxxxxxxxxxxxxx |  0x05  | Height |            Order         |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                               Signature (8 lines)                     |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//    |                               Hashes (height * 2)                     |
//    +--------+--------+--------+--------+--------+--------+--------+--------+
//

package scmp

import (
	"bytes"
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/pkt_sec_extn"
)

var _ common.Extension = (*AuthHashTreeExtn)(nil)

type AuthHashTreeExtn struct {
	*spse.BaseExtn
	Height    uint8
	Order     common.RawBytes
	Signature common.RawBytes
	Hashes    common.RawBytes
}

const (
	HeightLength    = 1
	OrderLength     = 3
	SignatureLength = 64
	HashLength      = 16

	HeightOffset    = spse.SecModeLength
	OrderOffset     = HeightOffset + HeightLength
	SignatureOffset = OrderOffset + OrderLength
	HashesOffset    = SignatureOffset + SignatureLength
)

func NewAuthHashTreeExtn(treeHeight uint8) *AuthHashTreeExtn {
	s := &AuthHashTreeExtn{
		BaseExtn: &spse.BaseExtn{
			SecMode: spse.ScmpAuthHashTree}}

	s.Height = treeHeight
	s.Order = make(common.RawBytes, OrderLength)
	s.Signature = make(common.RawBytes, SignatureLength)
	s.Hashes = make(common.RawBytes, int(treeHeight)*HashLength)
	return s
}

func (s AuthHashTreeExtn) SetOrder(order common.RawBytes) *common.Error {
	if len(order) != OrderLength {
		return common.NewError("Invalid order length", "len", len(order),
			"expected", OrderLength)
	}
	copy(s.Order, order)
	return nil

}

func (s AuthHashTreeExtn) SetSignature(signature common.RawBytes) *common.Error {
	if len(signature) != SignatureLength {
		return common.NewError("Invalid signature length", "len", len(signature),
			"expected", SignatureLength)
	}
	copy(s.Signature, signature)
	return nil

}

func (s AuthHashTreeExtn) SetHashes(hashes common.RawBytes) *common.Error {
	if len(hashes) != len(s.Hashes) {
		return common.NewError("Invalid hashes length", "len", len(hashes),
			"expected", len(s.Hashes))
	}
	copy(s.Hashes, hashes)
	return nil

}

func (s *AuthHashTreeExtn) Write(b common.RawBytes) *common.Error {
	if len(b) < s.Len() {
		return common.NewError("Buffer too short", "method", "SCMPAuthHashTreeExtn.Write")
	}
	b[0] = s.SecMode
	b[HeightOffset] = s.Height
	copy(b[OrderOffset:SignatureOffset], s.Order)
	copy(b[SignatureOffset:HashesOffset], s.Signature)
	copy(b[HashesOffset:], s.Hashes)
	return nil
}

func (s *AuthHashTreeExtn) Pack() (common.RawBytes, *common.Error) {
	b := make(common.RawBytes, s.Len())
	if err := s.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *AuthHashTreeExtn) Copy() common.Extension {
	c := NewAuthHashTreeExtn(s.Height)
	copy(c.Order, s.Order)
	copy(c.Signature, s.Signature)
	copy(c.Hashes, s.Hashes)
	return c
}

func (s *AuthHashTreeExtn) Len() int {
	return HashesOffset + len(s.Hashes)
}

func (s *AuthHashTreeExtn) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "AuthHashTreeExtn (%dB): SecMode: %d\n", s.Len(), s.SecMode)
	fmt.Fprintf(buf, " Height: %x", s.Height)
	fmt.Fprintf(buf, " Order: %s", s.Order.String())
	fmt.Fprintf(buf, " Signature: %s", s.Signature.String())
	fmt.Fprintf(buf, " Hashes: %s", s.Hashes.String())
	return buf.String()
}
