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

package scmp

import (
	"fmt"
	"time"

	//log "github.com/inconshreveable/log15"
	"gopkg.in/restruct.v1"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
)

var _ l4.L4Header = (*Hdr)(nil)

const (
	HdrLen = 16
)

const (
	ErrorSCMPHdrUnpack = "Failed to unpack SCMP header"
)

type Hdr struct {
	Class     Class           // SCMP message class
	Type      Type            // SCMP message type
	TotalLen  uint16          // Length of SCMP header + payload
	Checksum  common.RawBytes `struct:"[2]byte"`
	Timestamp uint64          // Time in µs since unix epoch
}

func NewHdr(ct ClassType, len int) *Hdr {
	now := uint64(time.Now().UnixNano())
	return &Hdr{
		Class: ct.Class, Type: ct.Type, TotalLen: HdrLen + uint16(len),
		Checksum: common.RawBytes{0, 0}, Timestamp: now / 1000,
	}
}

func HdrFromRaw(b common.RawBytes) (*Hdr, error) {
	h := &Hdr{}
	if err := restruct.Unpack(b, common.Order, h); err != nil {
		return nil, common.NewCError(ErrorSCMPHdrUnpack, "err", err)
	}
	return h, nil
}

func (h *Hdr) Validate(plen int) error {
	if plen+HdrLen != int(h.TotalLen) {
		return common.NewCError("SCMP header total length doesn't match",
			"expected", h.TotalLen, "actual", plen)
	}
	return nil
}

func (h *Hdr) SetPldLen(l int) {
	h.TotalLen = uint16(HdrLen + l)
}

func (h *Hdr) Write(b common.RawBytes) error {
	out, err := restruct.Pack(common.Order, h)
	if err != nil {
		return common.NewCError("Error packing SCMP header", "err", err)
	}
	if count := copy(b, out); count != HdrLen {
		return common.NewCError("Partial write of SCMP header",
			"expected(B)", HdrLen, "actual(B)", count)
	}
	return nil
}

func (h *Hdr) Pack(csum bool) (common.RawBytes, error) {
	b := make(common.RawBytes, HdrLen)
	if err := h.Write(b); err != nil {
		return nil, err
	}
	if csum {
		// Zero out the checksum field if this is being used for checksum calculation.
		b[6] = 0
		b[7] = 0
	}
	return b, nil
}

func (h *Hdr) GetCSum() common.RawBytes {
	return h.Checksum
}

func (h *Hdr) SetCSum(csum common.RawBytes) {
	h.Checksum = csum
}

func (h *Hdr) String() string {
	secs := int64(h.Timestamp / 1000000)
	nanos := int64((h.Timestamp % 1000000) * 1000)
	return fmt.Sprintf("Class=%v Type=%v TotalLen=%vB Checksum=%v Timestamp=%v",
		h.Class, h.Type.Name(h.Class), h.TotalLen, h.Checksum, time.Unix(secs, nanos))
}

func (h *Hdr) L4Type() common.L4ProtocolType {
	return common.L4SCMP
}

func (h *Hdr) L4Len() int {
	return HdrLen
}

func (h *Hdr) Reverse() {}

func (h *Hdr) Copy() l4.L4Header {
	return &Hdr{
		h.Class, h.Type, h.TotalLen, append(common.RawBytes(nil), h.Checksum...), h.Timestamp,
	}
}
