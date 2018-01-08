// Copyright 2016 ETH Zurich
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

package l4

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	UDPLen = 8
)

var _ L4Header = (*UDP)(nil)

type UDP struct {
	SrcPort  uint16
	DstPort  uint16
	TotalLen uint16
	Checksum common.RawBytes `struct:"[2]byte"`
}

func UDPFromRaw(b common.RawBytes) (*UDP, error) {
	u := &UDP{Checksum: make(common.RawBytes, 2)}
	if err := u.Parse(b); err != nil {
		return nil, common.NewBasicError("Error unpacking UDP header", err)
	}
	return u, nil
}

func (u *UDP) Validate(plen int) error {
	if plen+UDPLen != int(u.TotalLen) {
		return common.NewBasicError("UDP header total length doesn't match", nil,
			"expected", u.TotalLen, "actual", plen)
	}
	return nil
}

func (u *UDP) Parse(b common.RawBytes) error {
	offset := 0
	u.SrcPort = common.Order.Uint16(b[offset:])
	offset += 2
	u.DstPort = common.Order.Uint16(b[offset:])
	offset += 2
	u.TotalLen = common.Order.Uint16(b[offset:])
	offset += 2
	copy(u.Checksum, b[offset:])
	return nil
}

func (u *UDP) Pack(csum bool) (common.RawBytes, error) {
	b := make(common.RawBytes, UDPLen)
	if err := u.Write(b); err != nil {
		return nil, common.NewBasicError("Error packing UDP header", err)
	}
	if csum {
		// Zero out the checksum field if this is being used for checksum calculation.
		b[6] = 0
		b[7] = 0
	}
	return b, nil
}

func (u *UDP) Write(b common.RawBytes) error {
	offset := 0
	common.Order.PutUint16(b[offset:], u.SrcPort)
	offset += 2
	common.Order.PutUint16(b[offset:], u.DstPort)
	offset += 2
	common.Order.PutUint16(b[offset:], u.TotalLen)
	offset += 2
	copy(b[offset:], u.Checksum)
	return nil
}

func (u *UDP) GetCSum() common.RawBytes {
	return u.Checksum
}

func (u *UDP) SetCSum(csum common.RawBytes) {
	u.Checksum = csum
}

func (u *UDP) SetPldLen(pldLen int) {
	u.TotalLen = uint16(UDPLen + pldLen)
}

func (u *UDP) Copy() L4Header {
	return &UDP{u.SrcPort, u.DstPort, u.TotalLen, append(common.RawBytes(nil), u.Checksum...)}
}

func (u *UDP) L4Len() int {
	return UDPLen
}

func (u *UDP) L4Type() common.L4ProtocolType {
	return common.L4UDP
}

func (u *UDP) Reverse() {
	u.SrcPort, u.DstPort = u.DstPort, u.SrcPort
}

func (u *UDP) String() string {
	return fmt.Sprintf("SPort=%v DPort=%v TotalLen=%v Checksum=%v",
		u.SrcPort, u.DstPort, u.TotalLen, u.Checksum)
}
