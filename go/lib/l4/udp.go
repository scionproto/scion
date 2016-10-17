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
	"encoding/binary"
	"fmt"

	"gopkg.in/restruct.v1"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/libscion"
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	UDPLen = 8
)

var order = binary.BigEndian

type UDP struct {
	SrcPort  uint16
	DstPort  uint16
	TotalLen uint16
	Checksum util.RawBytes `struct:"[2]byte"`
}

func UDPFromRaw(b util.RawBytes) (*UDP, *util.Error) {
	u := &UDP{}
	if err := restruct.Unpack(b, order, u); err != nil {
		return nil, util.NewError("Error unpacking UDP header", "err", err)
	}
	if len(b) != int(u.TotalLen) {
		return nil, util.NewError("L4 UDP header total length doesn't match",
			"expected", u.TotalLen, "actual", len(b))
	}
	return u, nil
}

func (u *UDP) Pack() (util.RawBytes, *util.Error) {
	out, err := restruct.Pack(order, u)
	if err != nil {
		return nil, util.NewError("Error packing UDP header", "err", err)
	}
	return out, nil
}

func (u *UDP) CalcChecksum(srcAddr, dstAddr, pld util.RawBytes) (util.RawBytes, *util.Error) {
	out := make([]byte, 2)
	hdr, err := u.Pack()
	if err != nil {
		return nil, err
	}
	// Zero checksum
	hdr[6] = 0
	hdr[7] = 0
	sum := libscion.Checksum(srcAddr, dstAddr, []byte{byte(common.L4UDP)}, hdr, pld)
	order.PutUint16(out, sum)
	return out, nil
}

func (u *UDP) SetPldLen(pldLen int) {
	u.TotalLen = uint16(UDPLen + pldLen)
}

func (u *UDP) String() string {
	return fmt.Sprintf("SPort=%v DPort=%v TotalLen=%v Checksum=%v",
		u.SrcPort, u.DstPort, u.TotalLen, u.Checksum)
}
