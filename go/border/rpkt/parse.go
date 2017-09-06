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
	"github.com/netsec-ethz/scion/go/border/rcmn"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/assert"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/topology"
	"github.com/netsec-ethz/scion/go/lib/util"
)

// Parse handles the basic parsing of a packet.
func (rp *RtrPkt) Parse() error {
	if err := rp.parseBasic(); err != nil {
		return err
	}
	// TODO(kormat): support end2end extensions where the router is the
	// destination
	if err := rp.parseHopExtns(); err != nil {
		return err
	}
	// Pre-fetch attributes required by later stages of processing.
	if _, err := rp.DstIA(); err != nil {
		return err
	}
	if *rp.dstIA == *rp.Ctx.Conf.IA {
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
	if _, err := rp.UpFlag(); err != nil {
		return err
	}
	if _, err := rp.IFCurr(); err != nil {
		return err
	}
	if _, err := rp.IFNext(); err != nil {
		return err
	}
	if *rp.dstIA != *rp.Ctx.Conf.IA {
		// If the destination isn't local, parse the next interface ID as well.
		if _, err := rp.IFNext(); err != nil {
			return err
		}
	}
	rp.setDirTo()
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
		cerr := err.(*common.CError)
		if cerr.Desc == addr.ErrorBadHostAddrType {
			cerr.Data = scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadDstType, nil)
		}
		return err
	}
	// Set index for source host address and calculate its length.
	rp.idxs.srcHost = rp.idxs.dstHost + int(dstLen)
	if srcLen, err = addr.HostLen(rp.CmnHdr.SrcType); err != nil {
		cerr := err.(*common.CError)
		if cerr.Desc == addr.ErrorBadHostAddrType {
			cerr.Data = scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadSrcType, nil)
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
		return common.NewCError("Header length indicated in common header is too small",
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
		return common.NewCError(errExtChainTooLong, "curr", offset, "max", len(rp.Raw))
	}
	return nil
}

// setDirTo figures out which Dir a packet is going to, and sets the DirTo
// field accordingly.
func (rp *RtrPkt) setDirTo() {
	if assert.On {
		assert.Mustf(rp.DirFrom != rcmn.DirSelf, rp.ErrStr, "DirFrom must not be DirSelf.")
		assert.Mustf(rp.DirFrom != rcmn.DirUnset, rp.ErrStr, "DirFrom must not be DirUnset.")
		assert.Mustf(rp.ifCurr != nil, rp.ErrStr, "rp.ifCurr must not be nil.")
	}
	if *rp.dstIA != *rp.Ctx.Conf.IA {
		// Packet is not destined to the local AS, so it can't be DirSelf.
		if rp.DirFrom == rcmn.DirLocal {
			rp.DirTo = rcmn.DirExternal
		} else if rp.DirFrom == rcmn.DirExternal {
			// XXX(kormat): this logic might be too simple once a router can
			// have multiple interfaces.
			rp.DirTo = rcmn.DirLocal
		}
		return
	}
	// Local AS is the destination, so figure out if it's DirLocal or DirSelf.
	var taddr *topology.TopoAddr
	if rp.DirFrom == rcmn.DirExternal {
		taddr = rp.Ctx.Conf.Net.IFs[*rp.ifCurr].IFAddr
	} else {
		taddr = rp.Ctx.Conf.Net.LocAddr[rp.Ingress.LocIdx]
	}
	locIP := taddr.PublicAddrInfo(rp.Ingress.Dst.Overlay).IP
	if locIP.Equal(rp.dstHost.IP()) {
		rp.DirTo = rcmn.DirSelf
	} else {
		rp.DirTo = rcmn.DirLocal
	}
}
