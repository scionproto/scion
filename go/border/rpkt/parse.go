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
	"github.com/netsec-ethz/scion/go/lib/assert"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	ErrorHdrTooShort = "Header length indicated in common header is too small"
	ErrorExtOrder    = "Extension order is illegal"
	ErrorTooManyHBH  = "Too many hop-by-hop extensions"
)

func (rp *RtrPkt) Parse() *common.Error {
	if err := rp.parseBasic(); err != nil {
		return err
	}
	// TODO(kormat): support end2end extensions where the router is the destination
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
	if _, err := rp.IFNext(); err != nil {
		return err
	}
	if *rp.dstIA != *conf.C.IA {
		if _, err := rp.IFNext(); err != nil {
			return err
		}
	}
	rp.setDirTo()
	return nil
}

// Parse Common and address headers
func (rp *RtrPkt) parseBasic() *common.Error {
	var err *common.Error
	if err := rp.CmnHdr.Parse(rp.Raw); err != nil {
		return err
	}
	rp.idxs.srcIA = spkt.CmnHdrLen
	rp.idxs.srcHost = rp.idxs.srcIA + addr.IABytes
	srcLen, err := addr.HostLen(rp.CmnHdr.SrcType)
	if err != nil {
		if err.Desc == addr.ErrorBadHostAddrType {
			err.Data = scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadSrcType, nil)
		}
		return err
	}
	rp.idxs.dstIA = rp.idxs.srcHost + int(srcLen)
	rp.idxs.dstHost = rp.idxs.dstIA + addr.IABytes
	dstLen, err := addr.HostLen(rp.CmnHdr.DstType)
	if err != nil {
		if err.Desc == addr.ErrorBadHostAddrType {
			err.Data = scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadDstType, nil)
		}
		return err
	}
	addrLen := addr.IABytes + int(srcLen) + addr.IABytes + int(dstLen)
	addrPad := util.CalcPadding(addrLen, common.LineLen)
	rp.idxs.path = spkt.CmnHdrLen + addrLen + addrPad
	if rp.idxs.path > int(rp.CmnHdr.HdrLen) {
		// Can't generate SCMP error as we can't parse anything after the address header
		return common.NewError(ErrorHdrTooShort, "min", rp.idxs.path, "hdrLen", rp.CmnHdr.HdrLen)
	}
	return nil
}

func (rp *RtrPkt) parseHopExtns() *common.Error {
	rp.idxs.hbhExt = make([]extnIdx, 0, 4)
	rp.idxs.nextHdrIdx.Type = rp.CmnHdr.NextHdr
	rp.idxs.nextHdrIdx.Index = int(rp.CmnHdr.HdrLen)
	nextHdr := &rp.idxs.nextHdrIdx.Type
	offset := &rp.idxs.nextHdrIdx.Index
	count := 0
	for *offset < len(rp.Raw) {
		currHdr := *nextHdr
		if currHdr != common.HopByHopClass { // Reached end2end header or L4 protocol
			break
		}
		currExtn := common.ExtnType{Class: currHdr, Type: rp.Raw[*offset+2]}
		if currExtn == common.ExtnSCMPType {
			if count != 0 {
				sdata := scmp.NewErrData(scmp.C_Ext, scmp.T_E_BadExtOrder,
					&scmp.InfoExtIdx{Idx: uint8(len(rp.idxs.hbhExt))})
				return common.NewErrorData(ErrorExtOrder, sdata, "scmpIdx", count)
			}
		} else {
			count++
		}
		if count > common.ExtnMaxHBH {
			sdata := scmp.NewErrData(scmp.C_Ext, scmp.T_E_TooManyHopbyHop,
				&scmp.InfoExtIdx{Idx: uint8(len(rp.idxs.hbhExt))})
			return common.NewErrorData(ErrorTooManyHBH,
				sdata, "max", common.ExtnMaxHBH, "actual", count)
		}
		hdrLen := int((rp.Raw[*offset+1] + 1) * common.LineLen)
		e, err := rp.ExtnParseHBH(
			currExtn, *offset+common.ExtnSubHdrLen, *offset+hdrLen, len(rp.idxs.hbhExt))
		if err != nil {
			return err
		}
		if e != nil {
			e.RegisterHooks(&rp.hooks)
			rp.HBHExt = append(rp.HBHExt, e)
		}
		rp.idxs.hbhExt = append(rp.idxs.hbhExt, extnIdx{currExtn, *offset})
		*nextHdr = common.L4ProtocolType(rp.Raw[*offset])
		*offset += hdrLen
	}
	if *offset > len(rp.Raw) {
		// Can't generate SCMP error in general as we can't parse anything
		// after the hbh extensions (e.g. an l4 header).
		return common.NewError(ErrorExtChainTooLong, "curr", offset, "max", len(rp.Raw))
	}
	return nil
}

// Figure out which Dir a packet is going to.
func (rp *RtrPkt) setDirTo() {
	if assert.On {
		assert.Must(rp.DirFrom != DirSelf, rp.ErrStr("DirFrom must not be DirSelf."))
		assert.Must(rp.DirFrom != DirUnset, rp.ErrStr("DirFrom must not be DirUnset."))
		assert.Must(rp.ifCurr != nil, rp.ErrStr("rp.ifCurr must not be nil."))
	}
	if *rp.dstIA != *conf.C.IA {
		// Packet is not destined to the local AS, so it can't be DirSelf.
		if rp.DirFrom == DirLocal {
			rp.DirTo = DirExternal
		} else if rp.DirFrom == DirExternal {
			// XXX(kormat): this logic might be too simple once a router can
			// have multiple interfaces.
			rp.DirTo = DirLocal
		}
		return
	}
	// Local AS is the destination, so figure out if it's DirLocal or DirSelf.
	intf := conf.C.Net.IFs[*rp.ifCurr]
	var intfHost addr.HostAddr
	if rp.DirFrom == DirExternal {
		intfHost = addr.HostFromIP(intf.IFAddr.PublicAddr().IP)
	} else {
		intfHost = addr.HostFromIP(conf.C.Net.LocAddr[intf.LocAddrIdx].PublicAddr().IP)
	}
	if addr.HostEq(rp.dstHost, intfHost) {
		rp.DirTo = DirSelf
	} else {
		rp.DirTo = DirLocal
	}
}
