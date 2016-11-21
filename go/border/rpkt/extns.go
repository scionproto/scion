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

// This file handles parsing SCION extensions in received packets, and adding
// extensions to packets the router is creating.

package rpkt

import (
	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/scmp"
)

// rExtension extends common.ExtnBase, adding a method to retrieve the
// common.Extension from an rExtension, to allow conversion from RtrPkt to
// ScnPkt.
type rExtension interface {
	common.ExtnBase
	// Get or generate a common.Extension from this rExtension.
	GetExtn() (common.Extension, *common.Error)
	RegisterHooks(*hooks) *common.Error
}

const (
	// FIXME(kormat): remove when generic header walker is implemented.
	errExtChainTooLong = "Extension header chain longer than packet"
)

// extnParseHBH parses a specified hop-by-hop extension in a packet.
func (rp *RtrPkt) extnParseHBH(extType common.ExtnType,
	start, end, pos int) (rExtension, *common.Error) {
	switch {
	case extType == common.ExtnTracerouteType:
		return rTracerouteFromRaw(rp, start, end)
	case extType == common.ExtnOneHopPathType:
		return rOneHopPathFromRaw(rp)
	case extType == common.ExtnSCMPType:
		return rSCMPExtFromRaw(rp, start, end)
	default:
		// HBH not supported, so send an SCMP error in response.
		sdata := scmp.NewErrData(scmp.C_Ext, scmp.T_E_BadHopByHop,
			&scmp.InfoExtIdx{Idx: uint8(pos)})
		return nil, common.NewErrorData("Unsupported hop-by-hop extension", sdata, "type", extType)
	}
}

// extnAddHBH adds a hop-by-hop extension to a packet the router is creating.
// This method does not add SCMP data to errors as this is a packet that's been
// constructed locally.
func (rp *RtrPkt) extnAddHBH(e common.Extension) *common.Error {
	max := rp.maxHBHExtns()
	if len(rp.HBHExt) >= rp.maxHBHExtns() {
		return common.NewError("Too many hop-by-hop extensions", "curr", len(rp.HBHExt), "max", max)
	}
	if len(rp.HBHExt) > 1 && e.Type() == common.ExtnSCMPType {
		return common.NewError("Bad extension order - SCMP must be first",
			"idx", len(rp.HBHExt), "first", rp.HBHExt[0].Type())
	}
	// Find the last hop-by-hop extension, if any, so the new one can be
	// inserted after it.
	offset := int(rp.CmnHdr.HdrLen)
	var nextHdr *uint8 = (*uint8)(&rp.CmnHdr.NextHdr)
	for i, hIdx := range rp.idxs.hbhExt {
		nextHdr = &rp.Raw[hIdx.Index]
		offset = hIdx.Index + common.ExtnSubHdrLen + rp.HBHExt[i].Len()
	}
	// Check if the extension's length is legal
	eLen := e.Len() + common.ExtnSubHdrLen
	if eLen%common.LineLen != 0 {
		return common.NewError("HBH Ext length not multiple of line length",
			"lineLen", common.LineLen, "actual", eLen)
	}
	et := e.Type()
	// Set the preceding NextHdr field, whether it's in the common header, or a
	// preceding hop-by-hop extension.
	*nextHdr = uint8(et.Class)
	// Write extension sub-header into buffer
	rp.Raw[offset] = uint8(common.L4None)
	rp.Raw[offset+1] = uint8(eLen/common.LineLen) - 1
	rp.Raw[offset+2] = et.Type
	// Write extension into buffer
	if err := e.Write(rp.Raw[offset+common.ExtnSubHdrLen : offset+eLen]); err != nil {
		return err
	}
	// Parse extension back in, to set up appropriate metadata
	re, err := rp.extnParseHBH(e.Type(), offset+common.ExtnSubHdrLen,
		offset+eLen, len(rp.idxs.hbhExt))
	if err != nil {
		return err
	}
	re.RegisterHooks(&rp.hooks)
	rp.HBHExt = append(rp.HBHExt, re)
	// Update metadata indexes
	rp.idxs.hbhExt = append(rp.idxs.hbhExt, extnIdx{e.Type(), offset})
	rp.idxs.l4 = offset + eLen
	rp.idxs.pld = rp.idxs.l4
	return nil
}

// validateExtns validates the order and number of extensions.
func (rp *RtrPkt) validateExtns() *common.Error {
	max := rp.maxHBHExtns()
	count := len(rp.idxs.hbhExt)
	// Check if there are too many hop-by-hop extensions.
	if count > max {
		sdata := scmp.NewErrData(scmp.C_Ext, scmp.T_E_TooManyHopbyHop,
			&scmp.InfoExtIdx{Idx: uint8(count)})
		return common.NewErrorData("Too many hop-by-hop extensions",
			sdata, "max", common.ExtnMaxHBH, "actual", count)
	}
	// Check if there an SCMP hop-by-hop extension that isn't at index 0.
	for i, e := range rp.idxs.hbhExt {
		if e.Type == common.ExtnSCMPType && i > 0 {
			sdata := scmp.NewErrData(scmp.C_Ext, scmp.T_E_BadExtOrder,
				&scmp.InfoExtIdx{Idx: uint8(i)})
			return common.NewErrorData("Extension order is illegal", sdata, "scmpIdx", count)
		}
	}
	return nil
}

// maxHBHExtns calculates the maxiumum allowed number of hop-by-hop extensions.
// This is common.ExtnMaxHBH by default, but if the first HBH extension is
// SCMP, then the max is extended by 1. (This is so that any packet with the
// max number of hop-by-hop extensions can always be replied to with an SCMP
// error).
func (rp *RtrPkt) maxHBHExtns() int {
	max := common.ExtnMaxHBH
	if len(rp.HBHExt) > 1 && rp.HBHExt[0].Type() == common.ExtnSCMPType {
		max += 1
	}
	return max
}
