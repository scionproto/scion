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
	"bytes"
	"fmt"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
)

var _ common.Payload = (*Payload)(nil)

type Payload struct {
	ct      ClassType
	Meta    *Meta
	Info    Info
	CmnHdr  common.RawBytes
	AddrHdr common.RawBytes
	PathHdr common.RawBytes
	ExtHdrs common.RawBytes
	L4Hdr   common.RawBytes
}

func PldFromRaw(b common.RawBytes, ct ClassType) (*Payload, *common.Error) {
	var err *common.Error
	p := &Payload{ct: ct}
	buf := bytes.NewBuffer(b)
	if p.Meta, err = MetaFromRaw(buf.Next(MetaLen)); err != nil {
		return nil, err
	}
	if p.Info, err = ParseInfo(buf.Next(int(p.Meta.InfoLen)*common.LineLen), p.ct); err != nil {
		return nil, err
	}
	p.CmnHdr = buf.Next(int(p.Meta.CmnHdrLen) * common.LineLen)
	p.AddrHdr = buf.Next(int(p.Meta.AddrHdrLen) * common.LineLen)
	p.PathHdr = buf.Next(int(p.Meta.PathHdrLen) * common.LineLen)
	p.ExtHdrs = buf.Next(int(p.Meta.ExtHdrsLen) * common.LineLen)
	p.L4Hdr = buf.Next(int(p.Meta.L4HdrLen) * common.LineLen)
	log.Debug("PldFromRaw", "pld", p)
	return p, nil
}

type QuoteFunc func(RawBlock) common.RawBytes

func PldFromQuotes(ct ClassType, info Info, l4 common.L4ProtocolType, f QuoteFunc) *Payload {
	p := &Payload{ct: ct, Info: info}
	for _, blk := range classTypeQuotes(p.ct) {
		q := f(blk)
		switch blk {
		case RawCmnHdr:
			p.CmnHdr = q
		case RawAddrHdr:
			p.AddrHdr = q
		case RawPathHdr:
			p.PathHdr = q
		case RawExtHdrs:
			p.ExtHdrs = q
		case RawL4Hdr:
			p.L4Hdr = q
		}
	}
	p.Meta = &Meta{
		CmnHdrLen:  uint8(len(p.CmnHdr) / common.LineLen),
		AddrHdrLen: uint8(len(p.AddrHdr) / common.LineLen),
		PathHdrLen: uint8(len(p.PathHdr) / common.LineLen),
		ExtHdrsLen: uint8(len(p.ExtHdrs) / common.LineLen),
		L4HdrLen:   uint8(len(p.L4Hdr) / common.LineLen),
		L4Proto:    l4,
	}
	if info != nil {
		p.Meta.InfoLen = uint8(p.Info.Len() / common.LineLen)
	}
	return p
}

func (p *Payload) Copy() (common.Payload, *common.Error) {
	c := &Payload{ct: p.ct}
	c.Meta = p.Meta.Copy()
	c.Info = p.Info
	c.CmnHdr = append(common.RawBytes(nil), p.CmnHdr...)
	c.AddrHdr = append(common.RawBytes(nil), p.AddrHdr...)
	c.PathHdr = append(common.RawBytes(nil), p.PathHdr...)
	c.ExtHdrs = append(common.RawBytes(nil), p.ExtHdrs...)
	c.L4Hdr = append(common.RawBytes(nil), p.L4Hdr...)
	return c, nil
}

func (p *Payload) WritePld(b common.RawBytes) (int, *common.Error) {
	offset := 0
	if err := p.Meta.Write(b[offset:]); err != nil {
		return 0, err
	}
	offset += MetaLen
	if p.Info != nil {
		if count, err := p.Info.Write(b[offset:]); err != nil {
			return 0, err
		} else {
			offset += count
		}
	}
	copy(b[offset:], p.CmnHdr)
	offset += len(p.CmnHdr)
	copy(b[offset:], p.AddrHdr)
	offset += len(p.AddrHdr)
	copy(b[offset:], p.PathHdr)
	offset += len(p.PathHdr)
	copy(b[offset:], p.ExtHdrs)
	offset += len(p.ExtHdrs)
	copy(b[offset:], p.L4Hdr)
	return p.Len(), nil
}

func (p *Payload) Len() int {
	l := MetaLen
	if p.Info != nil {
		l += p.Info.Len()
	}
	l += int(p.Meta.CmnHdrLen) * common.LineLen
	l += int(p.Meta.AddrHdrLen) * common.LineLen
	l += int(p.Meta.PathHdrLen) * common.LineLen
	l += int(p.Meta.ExtHdrsLen) * common.LineLen
	l += int(p.Meta.L4HdrLen) * common.LineLen
	return l
}

func (p *Payload) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "Meta: %v\n", p.Meta)
	if p.Info != nil {
		fmt.Fprintf(buf, "Info: %v\n", p.Info)
	}
	if p.CmnHdr != nil {
		fmt.Fprintf(buf, "CmnHdr: %v\n", p.CmnHdr)
	}
	if p.AddrHdr != nil {
		fmt.Fprintf(buf, "AddrHdr: %v\n", p.AddrHdr)
	}
	if p.PathHdr != nil {
		fmt.Fprintf(buf, "PathHdr: %v\n", p.PathHdr)
	}
	if p.ExtHdrs != nil {
		fmt.Fprintf(buf, "ExtHdrs: %v\n", p.ExtHdrs)
	}
	if p.L4Hdr != nil {
		fmt.Fprintf(buf, "L4Hdr: %v\n", p.L4Hdr)
	}
	return buf.String()
}
