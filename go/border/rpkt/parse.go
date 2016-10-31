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

func (rp *RPkt) Parse() *util.Error {
	if err := rp.parseBasic(); err != nil {
		return err
	}
	if err := rp.parseHopExtns(); err != nil {
		return err
	}
	// Pre-fetch required attributes
	if _, err := rp.DstIA(); err != nil {
		return err
	}
	if *rp.dstIA == *conf.C.IA {
		if _, err := rp.DstHost(); err != nil {
			return err
		}
	}
	if _, err := rp.InfoF(); err != nil {
		return err
	}
	if _, err := rp.HopF(); err != nil {
		return err
	}
	if _, err := rp.UpFlag(); err != nil {
		return err
	}
	if _, err := rp.IFCurr(); err != nil {
		return err
	}
	if *rp.dstIA != *conf.C.IA {
		if _, err := rp.IFNext(); err != nil {
			return err
		}
	}
	return nil
}

// Parse Common and address headers
func (rp *RPkt) parseBasic() *util.Error {
	var err *util.Error
	if err := rp.CmnHdr.Parse(rp.Raw); err != nil {
		return err
	}
	rp.idxs.srcIA = spkt.CmnHdrLen
	rp.idxs.srcHost = rp.idxs.srcIA + addr.IABytes
	srcLen, err := addr.HostLen(rp.CmnHdr.SrcType)
	if err != nil {
		return err
	}
	rp.idxs.dstIA = rp.idxs.srcHost + int(srcLen)
	rp.idxs.dstHost = rp.idxs.dstIA + addr.IABytes
	dstLen, err := addr.HostLen(rp.CmnHdr.DstType)
	if err != nil {
		return err
	}
	addrLen := addr.IABytes + int(srcLen) + addr.IABytes + int(dstLen)
	addrPad := util.CalcPadding(addrLen, common.LineLen)
	rp.idxs.path = spkt.CmnHdrLen + addrLen + addrPad
	if rp.idxs.path > int(rp.CmnHdr.HdrLen) {
		return util.NewError(ErrorHdrTooShort, "min", rp.idxs.path, "hdrLen", rp.CmnHdr.HdrLen)
	}
	return nil
}

func (rp *RPkt) parseHopExtns() *util.Error {
	rp.idxs.hbhExt = make([]extnIdx, 0, 4)
	nextHdr := rp.CmnHdr.NextHdr
	offset := int(rp.CmnHdr.HdrLen)
	count := 0
	for offset < len(rp.Raw) {
		currHdr := nextHdr
		if currHdr != common.HopByHopClass { // Reached end2end header or L4 protocol
			break
		}
		currExtn := common.ExtnType{Class: currHdr, Type: rp.Raw[offset+2]}
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
		hdrLen := int((rp.Raw[offset+1] + 1) * common.LineLen)
		e, err := rp.ExtnParse(currExtn, offset, offset+hdrLen)
		if err != nil {
			return err
		}
		if e != nil {
			e.RegisterHooks(&rp.hooks)
			rp.HBHExt = append(rp.HBHExt, e)
		}
		rp.idxs.hbhExt = append(rp.idxs.hbhExt, extnIdx{currExtn, offset})
		nextHdr = common.L4ProtocolType(rp.Raw[offset])
		offset += hdrLen
	}
	if offset > len(rp.Raw) {
		return util.NewError(ErrorExtChainTooLong, "curr", offset, "max", len(rp.Raw))
	}
	rp.idxs.nextHdrIdx.Type = nextHdr
	rp.idxs.nextHdrIdx.Index = offset
	return nil
}
