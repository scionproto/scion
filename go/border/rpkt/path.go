// Copyright 2016 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

// This file handles the path header (parsing/validating/updating/etc).

package rpkt

import (
	"hash"
	"time"

	"github.com/scionproto/scion/go/border/ifstate"
	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/proto"
)

// validatePath validates the path header.
func (rp *RtrPkt) validatePath(dirFrom rcmn.Dir) error {
	// First check if there is a path
	if rp.infoF == nil || rp.hopF == nil {
		return common.NewBasicError("Path required",
			scmp.NewError(scmp.C_Path, scmp.T_P_PathRequired, nil, nil))
	}
	// There is a path, so ifCurr will be set
	if err := rp.validateLocalIF(rp.ifCurr); err != nil {
		return err
	}
	// Check for shorcuts in packets from core links
	if rp.infoF.Shortcut {
		currentLinkType := rp.Ctx.Conf.Net.IFs[*rp.ifCurr].Type
		if currentLinkType == proto.LinkType_core {
			return common.NewBasicError("Shortcut not allowed on core segment", nil)
		}
	}
	// A verify-only Hop Field cannot be used for routing.
	if rp.hopF.VerifyOnly {
		return common.NewBasicError("Hop field is VERIFY_ONLY",
			scmp.NewError(scmp.C_Path, scmp.T_P_NonRoutingHopF, rp.mkInfoPathOffsets(), nil))
	}
	// Check if Hop Field has expired.
	hopfExpiry := rp.infoF.Timestamp().Add(rp.hopF.ExpTime.ToDuration())
	if time.Now().After(hopfExpiry) {
		return common.NewBasicError(
			"Hop field expired",
			scmp.NewError(scmp.C_Path, scmp.T_P_ExpiredHopF, rp.mkInfoPathOffsets(), nil),
			"expiry", hopfExpiry,
		)
	}
	// Verify the Hop Field MAC.
	hfmac := rp.Ctx.Conf.HFMacPool.Get().(hash.Hash)
	err := rp.hopF.Verify(hfmac, rp.infoF.TsInt, rp.getHopFVer(dirFrom))
	rp.Ctx.Conf.HFMacPool.Put(hfmac)
	if err != nil && common.GetErrorMsg(err) == spath.ErrorHopFBadMac {
		err = scmp.NewError(scmp.C_Path, scmp.T_P_BadMac, rp.mkInfoPathOffsets(), err)
	}
	return err
}

// validateLocalIF makes sure a given interface ID exists in the local AS, and
// that it isn't revoked. Note that revocations are ignored if the packet's
// destination is this router.
func (rp *RtrPkt) validateLocalIF(ifid *common.IFIDType) error {
	if ifid == nil {
		return common.NewBasicError("validateLocalIF: Interface is nil", nil)
	}
	if _, ok := rp.Ctx.Conf.Topo.IFInfoMap[*ifid]; !ok {
		// No such interface.
		return common.NewBasicError(
			"Unknown IF",
			scmp.NewError(scmp.C_Path, scmp.T_P_BadIF, rp.mkInfoPathOffsets(), nil),
			"ifid", *ifid,
		)
	}
	for _, e := range rp.HBHExt {
		if e.Type() == common.ExtnOneHopPathType {
			// Ignore revocations if OneHopExtension is present
			return nil
		}
	}
	state, ok := ifstate.LoadState(*ifid)
	if !ok || state.Active {
		// Interface is not revoked
		return nil
	}
	// Interface is revoked.
	sRevInfo := state.SRevInfo
	if sRevInfo == nil {
		rp.Warn("No SRevInfo for revoked interface", "ifid", *ifid)
		return nil
	}
	revInfo, err := sRevInfo.RevInfo()
	if err != nil {
		rp.Warn("Could not parse RevInfo for interface", "ifid", *ifid, "err", err)
		return nil
	}
	err = revInfo.Active()
	if err != nil {
		if !common.IsTimeoutErr(err) {
			rp.Error("Error checking revocation", "err", err)
			return nil
		}
		// If the BR does not have a revocation for the current epoch, it considers
		// the interface as active until it receives a new revocation.
		newState := ifstate.NewInfo(*ifid, true, nil, nil)
		ifstate.UpdateIfNew(*ifid, state, newState)
		return nil
	}
	sinfo := scmp.NewInfoRevocation(
		uint16(rp.CmnHdr.CurrInfoF), uint16(rp.CmnHdr.CurrHopF), uint16(*ifid),
		rp.DirFrom == rcmn.DirExternal, state.RawSRev)
	return common.NewBasicError(
		errIntfRevoked,
		scmp.NewError(scmp.C_Path, scmp.T_P_RevokedIF, sinfo, nil),
		"ifid", ifid,
	)
}

// mkInfoPathOffsets is a helper function to create an scmp.InfoPathOffsets
// instance from the current packet.
func (rp *RtrPkt) mkInfoPathOffsets() scmp.Info {
	return &scmp.InfoPathOffsets{
		InfoF: uint16(rp.CmnHdr.CurrInfoF), HopF: uint16(rp.CmnHdr.CurrHopF),
		IfID: uint16(*rp.ifCurr), Ingress: rp.DirFrom == rcmn.DirExternal,
	}
}

// InfoF retrieves the current path Info Field if it isn't already known.
func (rp *RtrPkt) InfoF() (*spath.InfoField, error) {
	if rp.infoF == nil {
		for _, f := range rp.hooks.Infof {
			ret, infof, err := f()
			switch {
			case err != nil:
				return nil, err
			case ret == HookContinue:
				continue
			case ret == HookFinish:
				rp.infoF = infof
				return rp.infoF, nil
			}
		}
		// Check the common header path metadata validity, and if so extract
		// the current Info Field.
		hOff := rp.CmnHdr.InfoFOffBytes()
		switch {
		case rp.CmnHdr.CurrHopF == rp.CmnHdr.CurrInfoF:
			// There is no path, so do nothing.
		case hOff < rp.idxs.path: // Error
			return nil, common.NewBasicError(
				"Info field index too small",
				scmp.NewError(scmp.C_CmnHdr, scmp.T_C_BadInfoFOffset, nil, nil),
				"min", rp.idxs.path/common.LineLen, "actual", rp.CmnHdr.CurrInfoF,
			)
		case rp.CmnHdr.CurrInfoF > rp.CmnHdr.HdrLen: // Error
			return nil, common.NewBasicError(
				"Info field index too large",
				scmp.NewError(scmp.C_CmnHdr, scmp.T_C_BadInfoFOffset, nil, nil),
				"max", rp.CmnHdr.HdrLen, "actual", rp.CmnHdr.CurrInfoF,
			)
		case rp.CmnHdr.CurrInfoF < rp.CmnHdr.HdrLen: // Parse
			var err error
			if rp.infoF, err = spath.InfoFFromRaw(rp.Raw[hOff:]); err != nil {
				return nil, err
			}
		}
	}
	return rp.infoF, nil
}

// HopF retrieves the current path Hop Field if it isn't already known.
func (rp *RtrPkt) HopF() (*spath.HopField, error) {
	if rp.hopF == nil {
		for _, f := range rp.hooks.HopF {
			ret, hopf, err := f()
			switch {
			case err != nil:
				return nil, err
			case ret == HookContinue:
				continue
			case ret == HookFinish:
				rp.hopF = hopf
				return rp.hopF, nil
			}
		}

		hOff := rp.CmnHdr.HopFOffBytes()
		iOff := rp.CmnHdr.InfoFOffBytes()
		// Check if the common header path metadata is valid, and if so
		// extracts the current Hop Field.
		switch {
		case rp.CmnHdr.CurrHopF == rp.CmnHdr.CurrInfoF:
			// There is no path, so do nothing.
		case hOff < iOff+spath.InfoFieldLength: // Error
			return nil, common.NewBasicError(
				"Hop field index too small",
				scmp.NewError(scmp.C_CmnHdr, scmp.T_C_BadHopFOffset, nil, nil),
				"min", (iOff+spath.InfoFieldLength)/common.LineLen, "actual", rp.CmnHdr.CurrHopF,
			)
		case rp.CmnHdr.CurrHopF >= rp.CmnHdr.HdrLen: // Error
			return nil, common.NewBasicError(
				"Hop field index too large",
				scmp.NewError(scmp.C_CmnHdr, scmp.T_C_BadHopFOffset, nil, nil),
				"max", (rp.CmnHdr.HdrLenBytes()-spath.HopFieldLength)/common.LineLen,
				"actual", rp.CmnHdr.CurrHopF,
			)
		default: // Parse
			var err error
			if rp.hopF, err = spath.HopFFromRaw(rp.Raw[hOff:]); err != nil {
				return nil, err
			}
		}
	}
	return rp.hopF, nil
}

// getHopFVer retrieves the Hop Field (if any) required for verifying the MAC
// of the current Hop Field.
func (rp *RtrPkt) getHopFVer(dirFrom rcmn.Dir) common.RawBytes {
	ingress := dirFrom == rcmn.DirExternal
	var offset int
	if !rp.hopF.Xover || (rp.infoF.Shortcut && !rp.infoF.Peer) {
		offset = rp.getHopFVerNormalOffset()
	} else {
		switch rp.infoF.Peer {
		case true:
			// Peer shortcut paths have two extra HOFs; 1 for the peering
			// interface, and another from the upstream interface, used for
			// verification only.
			switch {
			case ingress && rp.infoF.ConsDir:
				offset = +1
			case ingress && !rp.infoF.ConsDir:
				offset = +2
			case !ingress && rp.infoF.ConsDir:
				offset = -2
			case !ingress && !rp.infoF.ConsDir:
				offset = -1
			}
		case false:
			// Non-peer shortcut paths have an extra HOF above the last hop,
			// used for verification of the last hop in that segment.
			switch {
			case ingress && rp.infoF.ConsDir:
				offset = -1
			case !ingress && !rp.infoF.ConsDir:
				offset = +1
			}
		}
	}
	return rp.hopFVerFromRaw(offset)
}

// getHopFVerNormalOffset is a helper function for getHopFVer, to handle cases
// where the verification Hop Field (if any) is directly before or after
// (depending on the ConsDir flag) the current Hop Field.
func (rp *RtrPkt) getHopFVerNormalOffset() int {
	iOff := rp.CmnHdr.InfoFOffBytes()
	hOff := rp.CmnHdr.HopFOffBytes()
	// If this is the last hop of an Up path, or the first hop of a Down path, there's no previous
	// HOF to verify against.
	if (!rp.infoF.ConsDir &&
		hOff == (iOff+spath.InfoFieldLength+int(rp.infoF.Hops-1)*spath.HopFieldLength)) ||
		(rp.infoF.ConsDir && hOff == (iOff+spath.InfoFieldLength)) {
		return 0
	}
	// Otherwise use the next/prev HOF based on the consDir flag.
	if !rp.infoF.ConsDir {
		return 1
	}
	return -1
}

// hopFVerFromRaw is a helper function for getHopFVer. It extracts the raw
// bytes of the specified Hop Field, excluding the leading flag byte.
func (rp *RtrPkt) hopFVerFromRaw(offset int) common.RawBytes {
	ans := make(common.RawBytes, common.LineLen-1)
	// If the offset is 0, a zero'd slice is returned.
	if offset != 0 {
		b := rp.Raw[(int(rp.CmnHdr.CurrHopF)+offset)*common.LineLen:]
		copy(ans, b[1:common.LineLen])
	}
	return ans
}

// IncPath increments the packet's path, if any. The bool return value is set
// to true if the segment changes (specifically if the packet's metadata is
// updated to the new segment).
func (rp *RtrPkt) IncPath() (bool, error) {
	if rp.infoF == nil {
		// Path is empty, nothing to increment.
		return false, nil
	}
	if assert.On {
		assert.Mustf(rp.consDirFlag != nil, rp.ErrStr, "rp.consDirFlag must not be nil")
	}
	var err error
	var hopF *spath.HopField
	// Initialize to the current InfoF and offset values.
	infoF := rp.infoF
	iOff := rp.CmnHdr.InfoFOffBytes()
	hOff := rp.CmnHdr.HopFOffBytes()
	hdrLen := rp.CmnHdr.HdrLenBytes()
	vOnly := 0
	origConsDir := *rp.consDirFlag
	for {
		hOff += spath.HopFieldLength
		if hOff-iOff > int(infoF.Hops*spath.HopFieldLength) {
			// Passed end of current segment, switch to next segment, and read
			// the new Info Field.
			iOff = hOff
			if infoF, err = spath.InfoFFromRaw(rp.Raw[iOff:]); err != nil {
				// Still return false as the metadata hasn't been updated to the new segment.
				return false, err
			}
			continue
		}
		// Read new Hop Field
		if hopF, err = spath.HopFFromRaw(rp.Raw[hOff:]); err != nil {
			return false, err
		}
		// Find first non-verify-only Hop Field.
		if !hopF.VerifyOnly {
			break
		}
		vOnly++
	}
	if hOff > hdrLen {
		return false, common.NewBasicError("New HopF offset > header length", nil,
			"max", hdrLen, "actual", hOff)
	}
	// Update common header, and packet's InfoF/HopF fields.
	segChgd := iOff != rp.CmnHdr.InfoFOffBytes()
	rp.CmnHdr.UpdatePathOffsets(rp.Raw, uint8(iOff/common.LineLen), uint8(hOff/common.LineLen))
	rp.infoF = infoF
	rp.hopF = hopF
	rp.IncrementedPath = true
	if segChgd {
		// Extract new ConsDir flag.
		rp.consDirFlag = nil
		if _, err = rp.ConsDirFlag(); err != nil {
			return segChgd, err
		}
	}
	// Extract the next interface ID.
	rp.ifNext = nil
	if _, err = rp.IFNext(); err != nil {
		return segChgd, err
	}
	// Check that there's no VERIFY_ONLY fields in the middle of a segment.
	if vOnly > 0 && !segChgd {
		return segChgd, common.NewBasicError("VERIFY_ONLY in middle of segment",
			scmp.NewError(scmp.C_Path, scmp.T_P_BadHopField, rp.mkInfoPathOffsets(), nil))
	}
	// Check that the segment didn't change from a down-segment to an up-segment.
	if origConsDir && !*rp.consDirFlag {
		return segChgd, common.NewBasicError("Switched from down-segment to up-segment",
			scmp.NewError(scmp.C_Path, scmp.T_P_BadSegment, rp.mkInfoPathOffsets(), nil))
	}
	return segChgd, nil
}

// ConsDirFlag retrieves the current path segment's ConsDir flag if not already known.
// (Consdir is defined as being the direction in which the segment was created.)
func (rp *RtrPkt) ConsDirFlag() (*bool, error) {
	if rp.consDirFlag != nil {
		return rp.consDirFlag, nil
	}
	// Try to get ConsDir flag from extensions
	for _, f := range rp.hooks.ConsDirFlag {
		ret, consDir, err := f()
		switch {
		case err != nil:
			return nil, err
		case ret == HookContinue:
			continue
		case ret == HookFinish:
			rp.consDirFlag = &consDir
			return rp.consDirFlag, nil
		}
	}
	// Try to get ConsDir flag from InfoField
	if rp.infoF == nil {
		return nil, nil
	}
	rp.consDirFlag = &rp.infoF.ConsDir
	return rp.consDirFlag, nil
}

// IFCurr retrieves the current interface ID from the packet headers/extensions,
// if not already known.
func (rp *RtrPkt) IFCurr() (*common.IFIDType, error) {
	if rp.ifCurr != nil {
		return rp.ifCurr, nil
	}
	if rp.consDirFlag != nil {
		// Try to get IFID from registered hooks.
		if ifid, err := rp.hookIF(*rp.consDirFlag, rp.hooks.IFCurr); err != nil {
			return nil, err
		} else if ifid != nil {
			return rp.checkSetCurrIF(ifid)
		}
		// Try to get IFID from HopField
		if rp.hopF != nil {
			var ingress bool
			switch rp.DirFrom {
			case rcmn.DirLocal:
				ingress = !*rp.consDirFlag
			case rcmn.DirExternal:
				ingress = *rp.consDirFlag
			default:
				return nil, common.NewBasicError("DirFrom value unsupported", nil,
					"val", rp.DirFrom)
			}
			if ingress {
				return rp.checkSetCurrIF(&rp.hopF.ConsIngress)
			}
			return rp.checkSetCurrIF(&rp.hopF.ConsEgress)
		}
	}
	return nil, nil
}

// checkSetCurrIF is a helper function that ensures the given interface ID is
// valid before setting the ifCurr field and returning the value.
func (rp *RtrPkt) checkSetCurrIF(ifid *common.IFIDType) (*common.IFIDType, error) {
	if ifid == nil {
		return nil, common.NewBasicError("No interface found", nil)
	}
	if _, ok := rp.Ctx.Conf.Net.IFs[*ifid]; !ok {
		return nil, common.NewBasicError("Unknown interface", nil, "ifid", *ifid)
	}
	rp.ifCurr = ifid
	return rp.ifCurr, nil
}

// IFNext retrieves the next interface ID if not already known. As this may be
// an interface in an external ISD-AS, this is not sanity-checked.
func (rp *RtrPkt) IFNext() (*common.IFIDType, error) {
	if rp.ifNext == nil && rp.consDirFlag != nil {
		var err error
		// Try to get IFID from registered hooks.
		if rp.ifNext, err = rp.hookIF(*rp.consDirFlag, rp.hooks.IFNext); err != nil {
			return nil, err
		} else if rp.ifNext != nil {
			return rp.ifNext, nil
		}
		// Get IFID from HopField
		if *rp.consDirFlag {
			rp.ifNext = &rp.hopF.ConsEgress
		} else {
			rp.ifNext = &rp.hopF.ConsIngress
		}
	}
	return rp.ifNext, nil
}

// hookIF is a helper function used by IFCurr/IFNext to run interface ID
// retrival hooks.
func (rp *RtrPkt) hookIF(consDir bool, hooks []hookIntf) (*common.IFIDType, error) {
	for _, f := range hooks {
		ret, intf, err := f(consDir, rp.DirFrom)
		switch {
		case err != nil:
			return nil, err
		case ret == HookContinue:
			continue
		case ret == HookFinish:
			return &intf, nil
		}
	}
	return nil, nil
}
