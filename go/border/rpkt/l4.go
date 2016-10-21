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

package rpkt

import (
	"bytes"
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	ErrorL4Unsupported   = "Unsupported L4 header type"
	ErrorL4InvalidChksum = "Invalid L4 checksum"
)

type L4Header interface {
	fmt.Stringer
}

func (p *RPkt) L4Hdr() (L4Header, *util.Error) {
	if p.l4 == nil {
		if found, err := p.findL4(); !found || err != nil {
			return nil, err
		}
		switch p.L4Type {
		case common.L4SCMP:
			scmpHdr, err := scmp.HdrFromRaw(p.Raw[p.idxs.l4:])
			if err != nil {
				return nil, err
			}
			p.l4 = scmpHdr
			p.idxs.pld = p.idxs.l4 + scmp.HdrLen
		case common.L4UDP:
			udp, err := l4.UDPFromRaw(p.Raw[p.idxs.l4:])
			if err != nil {
				return nil, err
			}
			p.l4 = udp
			p.idxs.pld = p.idxs.l4 + l4.UDPLen
		case common.L4SSP:
			p.l4 = &l4.SSP{}
		case common.L4TCP:
			p.l4 = &l4.TCP{}
		default:
			return nil, util.NewError(ErrorL4Unsupported, "type", p.L4Type)
		}
	}
	if err := p.verifyL4Chksum(); err != nil {
		return nil, err
	}
	return p.l4, nil
}

func (p *RPkt) findL4() (bool, *util.Error) {
	nextHdr := p.idxs.nextHdrIdx.Type
	offset := p.idxs.nextHdrIdx.Index
	for offset < len(p.Raw) {
		currHdr := nextHdr
		_, ok := common.L4Protocols[currHdr]
		if ok { // Reached L4 protocol
			p.L4Type = nextHdr
			p.idxs.l4 = offset
			break
		}
		currExtn := common.ExtnType{Class: currHdr, Type: p.Raw[offset+2]}
		hdrLen := int((p.Raw[offset+1] + 1) * common.LineLen)
		p.idxs.e2eExt = append(p.idxs.e2eExt, extnIdx{currExtn, offset})
		nextHdr = common.L4ProtocolType(p.Raw[offset])
		offset += hdrLen
	}
	if offset > len(p.Raw) {
		return false, util.NewError(ErrorExtChainTooLong, "curr", offset, "max", len(p.Raw))
	}
	p.idxs.nextHdrIdx.Type = nextHdr
	p.idxs.nextHdrIdx.Index = offset
	return true, nil
}

func (p *RPkt) verifyL4Chksum() *util.Error {
	switch v := p.l4.(type) {
	case *l4.UDP:
		src, dst, pld := p.getChksumInput()
		if csum, err := v.CalcChecksum(src, dst, pld); err != nil {
			return err
		} else if bytes.Compare(v.Checksum, csum) != 0 {
			return util.NewError(ErrorL4InvalidChksum,
				"expected", v.Checksum, "actual", csum, "proto", p.L4Type)
		}
	case *scmp.Hdr:
		src, dst, pld := p.getChksumInput()
		if csum, err := v.CalcChecksum(src, dst, pld); err != nil {
			return err
		} else if bytes.Compare(v.Checksum, csum) != 0 {
			return util.NewError(ErrorL4InvalidChksum,
				"expected", v.Checksum, "actual", csum, "proto", p.L4Type)
		}
	default:
		p.Debug("Skipping checksum verification of L4 header", "type", p.L4Type)
	}
	return nil
}

func (p *RPkt) getChksumInput() (src, dst, pld util.RawBytes) {
	srcLen, _ := addr.HostLen(p.CmnHdr.SrcType)
	dstLen, _ := addr.HostLen(p.CmnHdr.DstType)
	src = p.Raw[p.idxs.srcIA : p.idxs.srcIA+addr.IABytes+int(srcLen)]
	dst = p.Raw[p.idxs.dstIA : p.idxs.dstIA+addr.IABytes+int(dstLen)]
	pld = p.Raw[p.idxs.pld:]
	return
}

func (p *RPkt) updateL4() *util.Error {
	switch v := p.l4.(type) {
	case *l4.UDP:
		src, dst, pld := p.getChksumInput()
		v.SetPldLen(len(pld))
		csum, err := v.CalcChecksum(src, dst, pld)
		if err != nil {
			return err
		}
		v.Checksum = csum
		rawUdp, err := v.Pack()
		if err != nil {
			return err
		}
		copy(p.Raw[p.idxs.l4:], rawUdp)
	default:
		return util.NewError("Updating l4 payload not supported", "type", p.L4Type)
	}
	return nil
}
