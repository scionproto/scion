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
	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	ErrorHdrTooShort = "Header length indicated in common header is too small"
	ErrorExtOrder    = "Extension order is illegal"
	ErrorTooManyHBH  = "Too many hop-by-hop extensions"
)

func (p *Packet) Parse() *util.Error {
	if err := p.parseBasic(); err != nil {
		return err
	}
	if err := p.parseHopExtns(); err != nil {
		return err
	}
	// Pre-fetch required attributes
	if _, err := p.DstIA(); err != nil {
		return err
	}
	if *p.dstIA == *conf.C.IA {
		if _, err := p.DstHost(); err != nil {
			return err
		}
	}
	if _, err := p.InfoF(); err != nil {
		return err
	}
	if _, err := p.HopF(); err != nil {
		return err
	}
	if _, err := p.UpFlag(); err != nil {
		return err
	}
	if _, err := p.IFCurr(); err != nil {
		return err
	}
	if *p.dstIA != *conf.C.IA {
		if _, err := p.IFNext(); err != nil {
			return err
		}
	}
	return nil
}

// Parse Common and address headers
func (p *Packet) parseBasic() *util.Error {
	var err *util.Error
	if err := p.CmnHdr.Parse(p.Raw); err != nil {
		return err
	}
	p.idxs.srcIA = spkt.CmnHdrLen
	p.idxs.srcHost = p.idxs.srcIA + addr.IABytes
	srcLen, err := addr.HostLen(p.CmnHdr.SrcType)
	if err != nil {
		return err
	}
	p.idxs.dstIA = p.idxs.srcHost + int(srcLen)
	p.idxs.dstHost = p.idxs.dstIA + addr.IABytes
	dstLen, err := addr.HostLen(p.CmnHdr.DstType)
	if err != nil {
		return err
	}
	addrLen := addr.IABytes + int(srcLen) + addr.IABytes + int(dstLen)
	addrPad := util.CalcPadding(addrLen, common.LineLen)
	p.idxs.path = spkt.CmnHdrLen + addrLen + addrPad
	if p.idxs.path > int(p.CmnHdr.HdrLen) {
		return util.NewError(ErrorHdrTooShort, "min", p.idxs.path, "hdrLen", p.CmnHdr.HdrLen)
	}
	return nil
}

func (p *Packet) parseHopExtns() *util.Error {
	p.idxs.hbhExt = make([]extnIdx, 0, 4)
	nextHdr := p.CmnHdr.NextHdr
	offset := int(p.CmnHdr.HdrLen)
	count := 0
	for offset < len(p.Raw) {
		currHdr := nextHdr
		if currHdr != common.HopByHopClass { // Reached end2end header or L4 protocol
			break
		}
		currExtn := common.ExtnType{Class: currHdr, Type: p.Raw[offset+2]}
		if currExtn == common.ExtnSCMPType {
			if count != 0 {
				return util.NewError(ErrorExtOrder, "scmpIdx", count)
			}
		} else {
			count++
		}
		if count > ExtMaxHopByHop {
			return util.NewError(ErrorTooManyHBH, "max", ExtMaxHopByHop, "actual", count)
		}
		hdrLen := int((p.Raw[offset+1] + 1) * common.LineLen)
		e, err := p.ExtnParse(currExtn, offset, offset+hdrLen)
		if err != nil {
			return err
		}
		if e != nil {
			e.RegisterHooks(&p.hooks)
			p.HBHExt = append(p.HBHExt, e)
		}
		p.idxs.hbhExt = append(p.idxs.hbhExt, extnIdx{currExtn, offset})
		nextHdr = common.L4ProtocolType(p.Raw[offset])
		offset += hdrLen
	}
	if offset > len(p.Raw) {
		return util.NewError(ErrorExtChainTooLong, "curr", offset, "max", len(p.Raw))
	}
	p.idxs.nextHdrIdx.Type = nextHdr
	p.idxs.nextHdrIdx.Index = offset
	return nil
}
