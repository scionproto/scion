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

	"gopkg.in/restruct.v1"

	"github.com/netsec-ethz/scion/go/lib/common"
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

func UDPFromRaw(b common.RawBytes) (*UDP, *common.Error) {
	u := &UDP{}
	if err := restruct.Unpack(b, common.Order, u); err != nil {
		return nil, common.NewError("Error unpacking UDP header", "err", err)
	}
	return u, nil
}

func (u *UDP) Validate(plen int) *common.Error {
	if plen+UDPLen != int(u.TotalLen) {
		return common.NewError("UDP header total length doesn't match",
			"expected", u.TotalLen, "actual", plen)
	}
	return nil
}

func (u *UDP) Pack(csum bool) (common.RawBytes, *common.Error) {
	out, err := restruct.Pack(common.Order, u)
	if err != nil {
		return nil, common.NewError("Error packing UDP header", "err", err)
	}
	if csum {
		// Zero out the checksum field if this is being used for checksum calculation.
		out[6] = 0
		out[7] = 0
	}
	return out, nil
}

func (u *UDP) Write(b common.RawBytes) *common.Error {
	raw, err := u.Pack(false)
	if err != nil {
		return err
	}
	copy(b, raw)
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
