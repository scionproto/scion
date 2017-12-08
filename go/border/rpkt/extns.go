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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scmp"
)

// rExtension extends common.ExtnBase, adding a method to retrieve the
// common.Extension from an rExtension, to allow conversion from RtrPkt to
// ScnPkt.
type rExtension interface {
	common.ExtnBase
	// Get or generate a common.Extension from this rExtension.
	GetExtn() (common.Extension, error)
	RegisterHooks(*hooks) error
}

const (
	// FIXME(kormat): remove when generic header walker is implemented.
	ErrExtChainTooLong = "Extension header chain longer than packet"
)

// extnParseHBH parses a specified hop-by-hop extension in a packet.
func (rp *RtrPkt) extnParseHBH(extType common.ExtnType,
	start, end, pos int) (rExtension, error) {
	switch {
	case extType == common.ExtnTracerouteType:
		return rTracerouteFromRaw(rp, start, end)
	case extType == common.ExtnOneHopPathType:
		return rOneHopPathFromRaw(rp)
	case extType == common.ExtnSCMPType:
		return rSCMPExtFromRaw(rp, start, end)
	default:
		// HBH not supported, so send an SCMP error in response.
		return nil, common.NewBasicError(
			"Unsupported hop-by-hop extension",
			scmp.NewError(scmp.C_Ext, scmp.T_E_BadHopByHop, &scmp.InfoExtIdx{Idx: uint8(pos)}, nil),
			"type", extType,
		)
	}
}

// extnAddHBH adds a hop-by-hop extension to a packet the router is creating.
// This method does not add SCMP data to errors as this is a packet that's been
// constructed locally.
func (rp *RtrPkt) extnAddHBH(e common.Extension) error {
	max := rp.maxHBHExtns()
	if len(rp.HBHExt) >= rp.maxHBHExtns() {
		return common.NewBasicError("Too many hop-by-hop extensions", nil,
			"curr", len(rp.HBHExt), "max", max)
	}
	if len(rp.HBHExt) > 1 && e.Type() == common.ExtnSCMPType {
		return common.NewBasicError("Bad extension order - SCMP must be first", nil,
			"idx", len(rp.HBHExt), "first", rp.HBHExt[0].Type())
	}
	// Find the last hop-by-hop extension, if any, and write the extension
	offset, eLen, err := rp.extnWriteExtension(e, true)
	if err != nil {
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

// extnParseE2E parses a specified end-to-end extension in a packet.
func (rp *RtrPkt) extnParseE2E(extType common.ExtnType,
	start, end, pos int) (rExtension, error) {
	switch {
	case extType == common.ExtnSCIONPacketSecurityType:
		extn, err := parseSPSEfromRaw(rp, start, end, pos)
		if err != nil {
			return nil, err
		}
		return extn, nil
	default:
		// E2E not supported, so send an SCMP error in response.
		return nil, common.NewBasicError(
			"Unsupported end-to-end extension",
			scmp.NewError(scmp.C_Ext, scmp.T_E_BadEnd2End, &scmp.InfoExtIdx{Idx: uint8(pos)}, nil),
			"type", extType,
		)
	}
}

// extnAddE2E adds a end-to-end extension to a packet the router is creating.
func (rp *RtrPkt) extnAddE2E(e common.Extension) error {
	// Find the extension, if any, and write the extension
	offset, eLen, err := rp.extnWriteExtension(e, false)
	if err != nil {
		return err
	}
	// Parse extension back in, to set up appropriate metadata
	re, err := rp.extnParseE2E(e.Type(), offset+common.ExtnSubHdrLen,
		offset+eLen, len(rp.idxs.hbhExt)+len(rp.idxs.e2eExt))
	if err != nil {
		return err
	}
	re.RegisterHooks(&rp.hooks)
	rp.E2EExt = append(rp.E2EExt, re)
	// Update metadata indexes
	rp.idxs.e2eExt = append(rp.idxs.e2eExt, extnIdx{e.Type(), offset})
	rp.idxs.l4 = offset + eLen
	rp.idxs.pld = rp.idxs.l4
	return nil
}

// extnOffsetNew finds the last extension and returns the offset after
// that extension, as well as a pointer to the nextHdr field of that extension.
func (rp *RtrPkt) extnOffsetNew(isHBH bool) (int, *uint8, error) {
	if isHBH && len(rp.E2EExt) > 0 {
		return 0, nil, common.NewBasicError("HBH extension illegal to add after E2E extension", nil)
	}
	offset := rp.CmnHdr.HdrLenBytes()
	nextHdr := (*uint8)(&rp.CmnHdr.NextHdr)
	for i, hIdx := range rp.idxs.hbhExt {
		nextHdr = &rp.Raw[hIdx.Index]
		offset = hIdx.Index + common.ExtnSubHdrLen + rp.HBHExt[i].Len()
	}
	// This is a no-op if we're adding a hbh extension.
	for i, eIdx := range rp.idxs.e2eExt {
		nextHdr = &rp.Raw[eIdx.Index]
		offset = eIdx.Index + common.ExtnSubHdrLen + rp.E2EExt[i].Len()
	}
	return offset, nextHdr, nil
}

// extnWriteExtension writes the extension after the last extension and returns
// the offset of that extension, as well as the length of the written extension
func (rp *RtrPkt) extnWriteExtension(e common.Extension, isHBH bool) (int, int, error) {
	offset, nextHdr, err := rp.extnOffsetNew(isHBH)
	if err != nil {
		return 0, 0, err
	}
	eLen := e.Len() + common.ExtnSubHdrLen
	if eLen%common.LineLen != 0 {
		return 0, 0, common.NewBasicError("Ext length not multiple of line length", nil,
			"Class", e.Class(), "Type", e.Type(), "lineLen", common.LineLen, "actual", eLen)
	}
	et := e.Type()
	// Set the preceding NextHdr field, whether it's in the common header,
	// preceding hop-by-hop or end-to-end extension.
	*nextHdr = uint8(et.Class)
	// Write extension sub-header into buffer
	rp.Raw[offset] = uint8(common.L4None)
	rp.Raw[offset+1] = uint8(eLen / common.LineLen)
	rp.Raw[offset+2] = et.Type
	// Write extension into buffer
	if err := e.Write(rp.Raw[offset+common.ExtnSubHdrLen : offset+eLen]); err != nil {
		return 0, 0, err
	}
	return offset, eLen, err
}

// validateExtns validates the order and number of extensions.
func (rp *RtrPkt) validateExtns() error {
	max := rp.maxHBHExtns()
	count := len(rp.idxs.hbhExt)
	// Check if there are too many hop-by-hop extensions.
	if count > max {
		return common.NewBasicError(
			"Too many hop-by-hop extensions",
			scmp.NewError(scmp.C_Ext, scmp.T_E_TooManyHopbyHop,
				&scmp.InfoExtIdx{Idx: uint8(count)}, nil),
			"max", common.ExtnMaxHBH, "actual", count,
		)
	}
	// Check if there an SCMP hop-by-hop extension that isn't at index 0.
	for i, e := range rp.idxs.hbhExt {
		if e.Type == common.ExtnSCMPType && i > 0 {
			return common.NewBasicError(
				"Extension order is illegal",
				scmp.NewError(scmp.C_Ext, scmp.T_E_BadExtOrder,
					&scmp.InfoExtIdx{Idx: uint8(i)}, nil),
				"scmpIdx", count,
			)
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
