// Copyright 2018 ETH Zurich
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

package tpkt

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
)

type AddrHdr struct {
	DstIA, SrcIA     addr.IA
	DstHost, SrcHost addr.HostAddr
}

func NewAddrHdr(srcIA, srcHost, dstIA, dstHost string) *AddrHdr {
	dIA, _ := addr.IAFromString(dstIA)
	sIA, _ := addr.IAFromString(srcIA)
	// SVC address
	var dst addr.HostAddr
	dst = addr.HostSVCFromString(dstHost)
	if dst == addr.SvcNone {
		dst = addr.HostFromIPStr(dstHost)
	}
	return &AddrHdr{
		DstIA:   dIA,
		SrcIA:   sIA,
		DstHost: dst,
		SrcHost: addr.HostFromIPStr(srcHost),
	}
}

func ParseRawAddrHdr(b common.RawBytes, srcT, dstT addr.HostAddrType) (*AddrHdr, error) {
	a := &AddrHdr{}
	if _, err := a.Parse(b, srcT, dstT); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *AddrHdr) Parse(b common.RawBytes, srcT, dstT addr.HostAddrType) (int, error) {
	srcLen, err := addr.HostLen(srcT)
	if err != nil {
		return 0, err
	}
	dstLen, err := addr.HostLen(dstT)
	if err != nil {
		return 0, err
	}
	addrLen := util.PaddedLen(2*addr.IABytes+int(dstLen+srcLen), common.LineLen)
	if addrLen > len(b) {
		return 0, fmt.Errorf("AddrHdr: Buffer too short, expected=%d, actual=%d",
			addrLen, len(b))
	}
	a.DstIA = addr.IAFromRaw(b)
	a.SrcIA = addr.IAFromRaw(b[addr.IABytes:])
	offset := uint8(2 * addr.IABytes)
	a.DstHost, err = addr.HostFromRaw(b[offset:], dstT)
	if err != nil {
		return 0, err
	}
	offset += dstLen
	a.SrcHost, err = addr.HostFromRaw(b[offset:], srcT)
	if err != nil {
		return 0, err
	}
	offset += srcLen
	for _, x := range b[offset:addrLen] {
		if x != 0 {
			return 0, fmt.Errorf("AddrHdr: Padding is not zero, actual=%s", b[offset:addrLen])
		}
	}
	return addrLen, nil
}

func (a *AddrHdr) Len() int {
	return util.PaddedLen(2*addr.IABytes+a.DstHost.Size()+a.SrcHost.Size(), common.LineLen)
}

func (a *AddrHdr) Write(b common.RawBytes) int {
	offset := 0
	a.DstIA.Write(b[offset:])
	offset += addr.IABytes
	a.SrcIA.Write(b[offset:])
	offset += addr.IABytes
	// addr.HostAddr.Pack() is zero-copy, use it directly
	offset += copy(b[offset:], a.DstHost.Pack())
	offset += copy(b[offset:], a.SrcHost.Pack())
	// Zero memory padding
	addrPad := util.CalcPadding(offset, common.LineLen)
	zeroPad := b[offset : offset+addrPad]
	for i := range zeroPad {
		zeroPad[i] = 0
	}
	return offset + addrPad
}

func (a *AddrHdr) Equal(o *AddrHdr) bool {
	if a == nil || o == nil {
		return a == o
	}
	return a.DstIA.Equal(o.DstIA) &&
		a.SrcIA.Equal(o.SrcIA) &&
		a.DstHost.Equal(o.DstHost) &&
		a.SrcHost.Equal(o.SrcHost)
}

func (a *AddrHdr) String() string {
	return fmt.Sprintf("SrcIA: %s, SrcHost: %s, DstIA: %s, DstHost: %s",
		a.SrcIA, a.SrcHost, a.DstIA, a.DstHost)
}
