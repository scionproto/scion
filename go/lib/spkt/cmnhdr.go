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

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/scmp"
)

const (
	CmnHdrLen    = 8 // Bytes
	SCIONVersion = 0
)

type CmnHdr struct {
	Ver       uint8
	SrcType   uint8
	DstType   uint8
	TotalLen  uint16
	CurrInfoF uint8
	CurrHopF  uint8
	NextHdr   common.L4ProtocolType
	HdrLen    uint8
}

const (
	ErrorUnsuppVersion = "Unsupported SCION version"
)

func CmnHdrFromRaw(b common.RawBytes) (*CmnHdr, *common.Error) {
	c := &CmnHdr{}
	if err := c.Parse(b); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CmnHdr) Parse(b common.RawBytes) *common.Error {
	offset := 0
	verSrcDst := common.Order.Uint16(b[offset:])
	c.Ver = uint8(verSrcDst >> 12)
	c.SrcType = uint8(verSrcDst>>6) & 0x3F
	c.DstType = uint8(verSrcDst) & 0x3F
	offset += 2
	c.TotalLen = common.Order.Uint16(b[offset:])
	offset += 2
	c.CurrInfoF = b[offset]
	offset += 1
	c.CurrHopF = b[offset]
	offset += 1
	c.NextHdr = common.L4ProtocolType(b[offset])
	offset += 1
	c.HdrLen = b[offset]
	if c.Ver != SCIONVersion {
		// This can only usefully be replied to if the version specified is one
		// that the current router supports, but has deprecated.
		sdata := scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadVersion, nil)
		return common.NewErrorData(ErrorUnsuppVersion, sdata,
			"expected", SCIONVersion, "actual", c.Ver)
	}
	return nil
}

func (c *CmnHdr) Write(b common.RawBytes) {
	offset := 0
	var verSrcDst uint16
	verSrcDst = uint16(c.Ver&0xF)<<12 | uint16(c.SrcType&0x3F)<<6 | uint16(c.DstType&0x3F)
	common.Order.PutUint16(b[offset:], verSrcDst)
	offset += 2
	common.Order.PutUint16(b[offset:], c.TotalLen)
	offset += 2
	b[offset] = c.CurrInfoF
	offset += 1
	b[offset] = c.CurrHopF
	offset += 1
	b[offset] = byte(c.NextHdr)
	offset += 1
	b[offset] = c.HdrLen
}

func (c *CmnHdr) UpdatePathOffsets(b common.RawBytes, iOff, hOff uint8) {
	c.CurrInfoF = iOff
	c.CurrHopF = hOff
	b[4] = c.CurrInfoF
	b[5] = c.CurrHopF
}

func (c CmnHdr) String() string {
	return fmt.Sprintf(
		"Ver:%d Src:%d Dst:%d Total:%dB CurrInfoF:%dB CurrHopF:%dB NextHdr:%d HdrLen:%dB",
		c.Ver, c.SrcType, c.DstType, c.TotalLen, c.CurrInfoF, c.CurrHopF, c.NextHdr, c.HdrLen,
	)
}
