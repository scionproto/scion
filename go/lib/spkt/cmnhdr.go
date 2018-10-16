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

package spkt

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scmp"
)

const (
	CmnHdrLen    = 8 // Bytes
	SCIONVersion = 0
)

type CmnHdr struct {
	Ver       uint8
	DstType   addr.HostAddrType
	SrcType   addr.HostAddrType
	TotalLen  uint16
	HdrLen    uint8
	CurrInfoF uint8
	CurrHopF  uint8
	NextHdr   common.L4ProtocolType
}

const (
	ErrorUnsuppVersion = "Unsupported SCION version"
)

func CmnHdrFromRaw(b common.RawBytes) (*CmnHdr, error) {
	c := &CmnHdr{}
	if err := c.Parse(b); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CmnHdr) Parse(b common.RawBytes) error {
	// Check for minimum header length
	if len(b) < CmnHdrLen {
		return common.NewBasicError("Can't parse common header, buffer is too short", nil,
			"len", len(b))
	}
	offset := 0
	verDstSrc := common.Order.Uint16(b[offset:])
	c.Ver = uint8(verDstSrc >> 12)
	c.DstType = addr.HostAddrType(verDstSrc>>6) & 0x3F
	c.SrcType = addr.HostAddrType(verDstSrc) & 0x3F
	offset += 2
	c.TotalLen = common.Order.Uint16(b[offset:])
	offset += 2
	c.HdrLen = b[offset]
	offset += 1
	c.CurrInfoF = b[offset]
	offset += 1
	c.CurrHopF = b[offset]
	offset += 1
	c.NextHdr = common.L4ProtocolType(b[offset])
	if c.Ver != SCIONVersion {
		// This can only usefully be replied to if the version specified is one
		// that the current router supports, but has deprecated.
		return common.NewBasicError(
			ErrorUnsuppVersion,
			scmp.NewError(scmp.C_CmnHdr, scmp.T_C_BadVersion, nil, nil),
			"expected", SCIONVersion, "actual", c.Ver,
		)
	}
	return nil
}

func (c *CmnHdr) Write(b common.RawBytes) {
	offset := 0
	var verDstSrc uint16
	verDstSrc = uint16(c.Ver&0xF)<<12 | uint16(c.DstType&0x3F)<<6 | uint16(c.SrcType&0x3F)
	common.Order.PutUint16(b[offset:], verDstSrc)
	offset += 2
	common.Order.PutUint16(b[offset:], c.TotalLen)
	offset += 2
	b[offset] = c.HdrLen
	offset += 1
	b[offset] = c.CurrInfoF
	offset += 1
	b[offset] = c.CurrHopF
	offset += 1
	b[offset] = uint8(c.NextHdr)
}

func (c *CmnHdr) UpdatePathOffsets(b common.RawBytes, iOff, hOff uint8) {
	c.CurrInfoF = iOff
	c.CurrHopF = hOff
	b[5] = c.CurrInfoF
	b[6] = c.CurrHopF
}

func (c *CmnHdr) HdrLenBytes() int {
	return int(c.HdrLen) * common.LineLen
}

func (c *CmnHdr) InfoFOffBytes() int {
	return int(c.CurrInfoF) * common.LineLen
}

func (c *CmnHdr) HopFOffBytes() int {
	return int(c.CurrHopF) * common.LineLen
}

func (c CmnHdr) String() string {
	return fmt.Sprintf(
		"Ver:%d Dst:%s Src:%s TotalLen:%dB HdrLen: %dB CurrInfoF:%dB CurrHopF:%dB NextHdr:%s",
		c.Ver, c.DstType, c.SrcType, c.TotalLen, c.HdrLen, c.CurrInfoF, c.CurrHopF, c.NextHdr,
	)
}
