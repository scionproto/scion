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

// This file handles the basic parsing of packets, from common & address
// headers, to hop-by-hop extensions headers.

package rpkt

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/util"
)

// Parse handles the basic parsing of a packet.
func (rp *RtrPkt) Parse() error {
	if err := rp.parseBasic(); err != nil {
		return err
	}
	if err := rp.parseHopExtns(); err != nil {
		return err
	}
	// Pre-fetch attributes required by later stages of processing.
	if _, err := rp.DstIA(); err != nil {
		return err
	}
	if rp.dstIA.Eq(rp.Ctx.Conf.IA) {
		// If the destination is local, parse the destination host as well.
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
	if _, err := rp.ConsDirFlag(); err != nil {
		return err
	}
	if _, err := rp.IFCurr(); err != nil {
		return err
	}
	if _, err := rp.IFNext(); err != nil {
		return err
	}
	return nil
}

// parseBasic handles the parsing of the common and address headers.
func (rp *RtrPkt) parseBasic() error {
	var err error
	var dstLen, srcLen uint8
	// Parse common header.
	if err = rp.CmnHdr.Parse(rp.Raw); err != nil {
		return err
	}
	// Set indexes for destination and source ISD-ASes.
	rp.idxs.dstIA = spkt.CmnHdrLen
	rp.idxs.srcIA = rp.idxs.dstIA + addr.IABytes
	// Set index for destination host address and calculate its length.
	rp.idxs.dstHost = rp.idxs.srcIA + addr.IABytes
	if dstLen, err = addr.HostLen(rp.CmnHdr.DstType); err != nil {
		if common.GetErrorMsg(err) == addr.ErrorBadHostAddrType {
			err = scmp.NewError(scmp.C_CmnHdr, scmp.T_C_BadDstType, nil, err)
		}
		return err
	}
	// Set index for source host address and calculate its length.
	rp.idxs.srcHost = rp.idxs.dstHost + int(dstLen)
	if srcLen, err = addr.HostLen(rp.CmnHdr.SrcType); err != nil {
		if common.GetErrorMsg(err) == addr.ErrorBadHostAddrType {
			err = scmp.NewError(scmp.C_CmnHdr, scmp.T_C_BadSrcType, nil, err)
		}
		return err
	}
	// Set index for path header.
	addrLen := int(addr.IABytes*2 + dstLen + srcLen)
	addrPad := util.CalcPadding(addrLen, common.LineLen)
	hdrLen := rp.CmnHdr.HdrLenBytes()
	rp.idxs.path = spkt.CmnHdrLen + addrLen + addrPad
	if rp.idxs.path > hdrLen {
		// Can't generate SCMP error as we can't parse anything after the address header
		return common.NewBasicError("Header length indicated in common header is too small", nil,
			"min", rp.idxs.path, "hdrLen", rp.CmnHdr.HdrLen, "byteSize", hdrLen)
	}
	return nil
}

// parseHopExtns walks the header chain, parsing hop-by-hop extensions,
// stopping at the first non-HBH extension/L4 protocol header.
func (rp *RtrPkt) parseHopExtns() error {
	// +1 to allow for a leading SCMP hop-by-hop extension.
	rp.idxs.hbhExt = make([]extnIdx, 0, common.ExtnMaxHBH+1)
	rp.idxs.nextHdrIdx.Type = rp.CmnHdr.NextHdr
	rp.idxs.nextHdrIdx.Index = rp.CmnHdr.HdrLenBytes()
	nextHdr := &rp.idxs.nextHdrIdx.Type
	offset := &rp.idxs.nextHdrIdx.Index
	for *offset < len(rp.Raw) {
		currHdr := *nextHdr
		if currHdr != common.HopByHopClass { // Reached end2end header or L4 protocol
			break
		}
		currExtn := common.ExtnType{Class: currHdr, Type: rp.Raw[*offset+2]}
		hdrLen := int(rp.Raw[*offset+1]) * common.LineLen
		e, err := rp.extnParseHBH(
			currExtn, *offset+common.ExtnSubHdrLen, *offset+hdrLen, len(rp.idxs.hbhExt))
		if err != nil {
			return err
		}
		e.RegisterHooks(&rp.hooks)
		rp.HBHExt = append(rp.HBHExt, e)
		rp.idxs.hbhExt = append(rp.idxs.hbhExt, extnIdx{currExtn, *offset})
		*nextHdr = common.L4ProtocolType(rp.Raw[*offset])
		*offset += hdrLen
	}
	if *offset > len(rp.Raw) {
		// FIXME(kormat): Can't generate SCMP error in general as we can't
		// parse anything after the hbh extensions (e.g. a layer 4 header).
		return common.NewBasicError(ErrExtChainTooLong, nil, "curr", *offset, "max", len(rp.Raw))
	}
	return nil
}
