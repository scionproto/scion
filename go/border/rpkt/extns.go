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
	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/scmp"
)

type RExtension interface {
	common.ExtnBase
	GetExtn() (common.Extension, *common.Error)
	RegisterHooks(*Hooks) *common.Error
}

const (
	ErrorBadHopByHop     = "Unsupported hop-by-hop extension"
	ErrorBadEnd2End      = "Unsupported end2end extension"
	ErrorExtChainTooLong = "Extension header chain longer than packet"
)

var ExtHBHKnown = map[common.ExtnType]bool{
	common.ExtnTracerouteType: true,
	common.ExtnSCMPType:       true,
	common.ExtnSIBRAType:      true,
}

func (rp *RtrPkt) ExtnParseHBH(extType common.ExtnType,
	start, end, pos int) (RExtension, *common.Error) {
	switch {
	case extType == common.ExtnTracerouteType:
		return RTracerouteFromRaw(rp, start, end)
	case extType == common.ExtnOneHopPathType:
		return ROneHopPathFromRaw(rp)
	case extType == common.ExtnSCMPType:
		return RSCMPExtFromRaw(rp, start, end)
	default:
		sdata := scmp.NewErrData(scmp.C_Ext, scmp.T_E_BadHopByHop,
			&scmp.InfoExtIdx{Idx: uint8(pos)})
		return nil, common.NewErrorData(ErrorBadHopByHop, sdata, "type", extType)
	}
}

func (rp *RtrPkt) extnAddHBH(e common.Extension) *common.Error {
	max := common.ExtnMaxHBH
	if len(rp.HBHExt) > 1 && rp.HBHExt[0].Type() == common.ExtnSCMPType {
		max += 1
	}
	if len(rp.HBHExt) >= max {
		// No point in generating an SCMP error, as this is a packet we're constructing locally.
		return common.NewError(ErrorTooManyHBH, "curr", len(rp.HBHExt), "max", max)
	}
	if len(rp.HBHExt) > 1 && e.Type() == common.ExtnSCMPType {
		return common.NewError("Bad extension order - SCMP must be first",
			"idx", len(rp.HBHExt), "first", rp.HBHExt[0].Type())
	}
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
	re, err := rp.ExtnParseHBH(e.Type(), offset+common.ExtnSubHdrLen,
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
