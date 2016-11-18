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
	"time"

	log "github.com/inconshreveable/log15"
	logext "github.com/inconshreveable/log15/ext"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/spkt"
)

func RtrPktFromScnPkt(sp *spkt.ScnPkt, dirTo Dir) (*RtrPkt, *common.Error) {
	rp := NewRtrPkt()
	hdrLen := sp.HdrLen()
	totalLen := sp.TotalLen()
	rp.TimeIn = time.Now()
	rp.Id = logext.RandId(4)
	rp.Logger = log.New("rpkt", rp.Id)
	rp.DirFrom = DirSelf
	rp.DirTo = dirTo
	// Fill in common header and write it out
	rp.CmnHdr.SrcType = sp.SrcHost.Type()
	rp.CmnHdr.DstType = sp.DstHost.Type()
	rp.CmnHdr.HdrLen = uint8(hdrLen)
	rp.CmnHdr.TotalLen = uint16(totalLen)
	rp.CmnHdr.NextHdr = common.L4None
	rp.CmnHdr.CurrInfoF = uint8(hdrLen)
	rp.CmnHdr.CurrHopF = uint8(hdrLen)
	// Fill in address header and indexes
	rp.idxs.srcIA = spkt.CmnHdrLen
	rp.srcIA = sp.SrcIA
	rp.idxs.srcHost = rp.idxs.srcIA + addr.IABytes
	rp.srcHost = sp.SrcHost
	rp.idxs.dstIA = rp.idxs.srcHost + rp.srcHost.Size()
	rp.dstIA = sp.DstIA
	rp.idxs.dstHost = rp.idxs.dstIA + addr.IABytes
	rp.dstHost = sp.DstHost
	rp.srcIA.Write(rp.Raw[rp.idxs.srcIA:])
	copy(rp.Raw[rp.idxs.srcHost:], rp.srcHost.Pack())
	rp.dstIA.Write(rp.Raw[rp.idxs.dstIA:])
	copy(rp.Raw[rp.idxs.dstHost:], rp.dstHost.Pack())
	// Fill in path
	rp.idxs.path = spkt.CmnHdrLen + sp.AddrLen()
	if sp.Path != nil {
		copy(rp.Raw[rp.idxs.path:], sp.Path.Raw)
		rp.CmnHdr.CurrInfoF = uint8(rp.idxs.path) + sp.Path.InfOff
		rp.CmnHdr.CurrHopF = uint8(rp.idxs.path) + sp.Path.HopOff
	}
	// Fill in extensions
	rp.idxs.l4 = hdrLen // Will be updated as necessary by ExtnAddHBH
	for _, se := range sp.HBHExt {
		if err := rp.extnAddHBH(se); err != nil {
			return nil, err
		}
	}
	// Fill in L4 Header
	rp.idxs.pld = hdrLen // Will be updated as necessary by AddL4
	if sp.L4 != nil {
		if err := rp.addL4(sp.L4); err != nil {
			return nil, err
		}
		// Fill in payload
		if err := rp.SetPld(sp.Pld); err != nil {
			return nil, err
		}
	} else {
		// Trim buffer to the end of the last extension header (or path header,
		// if there are no extensions)
		rp.Raw = rp.Raw[:rp.idxs.l4]
		rp.CmnHdr.TotalLen = uint16(len(rp.Raw))
		rp.CmnHdr.Write(rp.Raw)
	}
	return rp, nil
}

func (rp *RtrPkt) addL4(l4h l4.L4Header) *common.Error {
	rp.L4Type = l4h.L4Type()
	rp.l4 = l4h
	// Reset buffer to full size
	rp.Raw = rp.Raw[:cap(rp.Raw)-1]
	// Write L4 header into buffer
	if err := rp.l4.Write(rp.Raw[rp.idxs.l4:]); err != nil {
		return err
	}
	// Locate the last extension in the packet, whether HBH (hop-by-hop) or E2E (end-to-end),
	// so that its sub-header can be updated with the L4 prototcol type.
	rp.idxs.pld = rp.idxs.l4 + l4h.L4Len()
	var nextHdr *uint8
	for _, eIdx := range rp.idxs.hbhExt {
		nextHdr = &rp.Raw[eIdx.Index]
	}
	for _, eIdx := range rp.idxs.e2eExt {
		nextHdr = &rp.Raw[eIdx.Index]
	}
	if nextHdr != nil {
		// Last extension sub-header found, update its nextHdr field.
		*nextHdr = uint8(rp.L4Type)
	} else {
		// There are no extensions, so the common header NextHDr field needs to be updated.
		rp.CmnHdr.NextHdr = rp.L4Type
	}
	// Trim buffer to the end of the L4 header.
	rp.Raw = rp.Raw[:rp.idxs.pld]
	rp.CmnHdr.TotalLen = uint16(len(rp.Raw))
	rp.CmnHdr.Write(rp.Raw)
	return nil
}

func (rp *RtrPkt) SetPld(pld common.Payload) *common.Error {
	rp.pld = pld
	var plen int
	if rp.pld != nil {
		// Reset buffer to full size
		rp.Raw = rp.Raw[:cap(rp.Raw)-1]
		// Write payload into buffer
		var err *common.Error
		plen, err = rp.pld.Write(rp.Raw[rp.idxs.pld:])
		if err != nil {
			return err
		}
	}
	// Trim buffer to the end of the payload.
	rp.Raw = rp.Raw[:rp.idxs.pld+plen]
	// Update headers
	if err := rp.updateL4(); err != nil {
		return err
	}
	rp.CmnHdr.TotalLen = uint16(len(rp.Raw))
	rp.CmnHdr.Write(rp.Raw)
	return nil
}
