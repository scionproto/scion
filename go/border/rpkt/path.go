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

// This file handles the path header (parsing/validating/updating/etc).

package rpkt

import (
	"time"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/assert"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/spath"
)

// validatePath validates the path header.
func (rp *RtrPkt) validatePath(dirFrom Dir) *common.Error {
	if assert.On {
		assert.Must(rp.ifCurr != nil, rp.ErrStr("rp.ifCurr must not be nil"))
	}
	// First check to make sure the current interface is known and not revoked.
	if err := rp.validateLocalIF(rp.ifCurr); err != nil {
		return err
	}
	if rp.infoF == nil || rp.hopF == nil {
		// If there's no path, then there's nothing to check.
		if rp.DirTo == DirSelf {
			// An empty path is legitimate when the packet's destination is
			// this router.
			return nil
		}
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_PathRequired, nil)
		return common.NewErrorData("Path required", sdata)
	}
	// A verify-only Hop Field cannot be used for routing.
	if rp.hopF.VerifyOnly {
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_NonRoutingHopF, rp.mkInfoPathOffsets())
		return common.NewErrorData("Hop field is VERIFY_ONLY", sdata)
	}
	// A forward-only Hop Field cannot be used for local delivery.
	if rp.hopF.ForwardOnly && rp.dstIA == conf.C.IA {
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_DeliveryFwdOnly, rp.mkInfoPathOffsets())
		return common.NewErrorData("Hop field is FORWARD_ONLY", sdata)
	}
	// Check if Hop Field has expired.
	hopfExpiry := rp.infoF.Timestamp().Add(
		time.Duration(rp.hopF.ExpTime) * spath.ExpTimeUnit * time.Second)
	if time.Now().After(hopfExpiry) {
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_ExpiredHopF, rp.mkInfoPathOffsets())
		return common.NewErrorData("Hop field expired", sdata, "expiry", hopfExpiry)
	}
	// Verify the Hop Field MAC.
	err := rp.hopF.Verify(conf.C.HFGenBlock, rp.infoF.TsInt, rp.getHopFVer(dirFrom))
	if err != nil && err.Desc == spath.ErrorHopFBadMac {
		err.Data = scmp.NewErrData(scmp.C_Path, scmp.T_P_BadMac, rp.mkInfoPathOffsets())
	}
	return err
}

// validateLocalIF makes sure a given interface ID exists in the local AS, and
// that it isn't revoked. Note that revocations are ignored if the packet's
// destination is this router.
func (rp *RtrPkt) validateLocalIF(ifid *spath.IntfID) *common.Error {
	if ifid == nil {
		return common.NewError("validateLocalIF: Interface is nil")
	}
	if _, ok := conf.C.TopoMeta.IFMap[int(*ifid)]; !ok {
		// No such interface.
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_BadIF, rp.mkInfoPathOffsets())
		return common.NewErrorData("Unknown IF", sdata, "ifid", ifid)
	}
	conf.C.IFStates.RLock()
	info, ok := conf.C.IFStates.M[*ifid]
	conf.C.IFStates.RUnlock()
	if !ok || info.P.Active() || rp.DirTo == DirSelf {
		// Either the interface isn't revoked, or the packet is to this
		// router, in which case revocations are ignored to allow communication
		// with the router.
		return nil
	}
	// Interface is revoked.
	sinfo := scmp.NewInfoRevocation(
		uint16(rp.CmnHdr.CurrInfoF), uint16(rp.CmnHdr.CurrHopF), uint16(*ifid),
		rp.DirFrom == DirExternal, info.RawRev)
	sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_RevokedIF, sinfo)
	return common.NewErrorData(errIntfRevoked, sdata, "ifid", ifid)
}

// mkInfoPathOffsets is a helper function to create an scmp.InfoPathOffsets
// instance from the current packet.
func (rp *RtrPkt) mkInfoPathOffsets() scmp.Info {
	return &scmp.InfoPathOffsets{
		InfoF: uint16(rp.CmnHdr.CurrInfoF), HopF: uint16(rp.CmnHdr.CurrHopF),
		IfID: uint16(*rp.ifCurr), Ingress: rp.DirFrom == DirExternal,
	}
}

// InfoF retrieves the current path Info Field if it isn't already known.
func (rp *RtrPkt) InfoF() (*spath.InfoField, *common.Error) {
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
		switch {
		case rp.CmnHdr.CurrHopF == rp.CmnHdr.CurrInfoF:
			// There is no path, so do nothing.
		case int(rp.CmnHdr.CurrInfoF) < rp.idxs.path: // Error
			sdata := scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadInfoFOffset, nil)
			return nil, common.NewErrorData("Info field offset too small", sdata,
				"min", rp.idxs.path, "actual", rp.CmnHdr.CurrInfoF)
		case rp.CmnHdr.CurrInfoF > rp.CmnHdr.HdrLen: // Error
			sdata := scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadInfoFOffset, nil)
			return nil, common.NewErrorData("Info field offset too large", sdata,
				"max", rp.CmnHdr.HdrLen, "actual", rp.CmnHdr.CurrInfoF)
		case rp.CmnHdr.CurrInfoF < rp.CmnHdr.HdrLen: // Parse
			var err *common.Error
			if rp.infoF, err = spath.InfoFFromRaw(rp.Raw[rp.CmnHdr.CurrInfoF:]); err != nil {
				return nil, err
			}
		}
	}
	return rp.infoF, nil
}

// HopF retrieves the current path Hop Field if it isn't already known.
func (rp *RtrPkt) HopF() (*spath.HopField, *common.Error) {
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
		// Check if the common header path metadata is valid, and if so
		// extracts the current Hop Field.
		switch {
		case rp.CmnHdr.CurrHopF == rp.CmnHdr.CurrInfoF:
			// There is no path, so do nothing.
		case rp.CmnHdr.CurrHopF < rp.CmnHdr.CurrInfoF+spath.InfoFieldLength: // Error
			sdata := scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadHopFOffset, nil)
			return nil, common.NewErrorData("Hop field offset too small", sdata,
				"min", rp.CmnHdr.CurrInfoF+spath.InfoFieldLength, "actual", rp.CmnHdr.CurrHopF)
		case rp.CmnHdr.CurrHopF >= rp.CmnHdr.HdrLen: // Error
			sdata := scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadHopFOffset, nil)
			return nil, common.NewErrorData("Hop field offset too large", sdata,
				"max", rp.CmnHdr.HdrLen-spath.HopFieldLength, "actual", rp.CmnHdr.CurrHopF)
		default: // Parse
			var err *common.Error
			if rp.hopF, err = spath.HopFFromRaw(rp.Raw[rp.CmnHdr.CurrHopF:]); err != nil {
				return nil, err
			}
		}
	}
	return rp.hopF, nil
}

// getHopFVer retrieves the Hop Field (if any) required for verifying the MAC
// of the current Hop Field.
func (rp *RtrPkt) getHopFVer(dirFrom Dir) common.RawBytes {
	ingress := dirFrom == DirExternal
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
			case ingress && rp.infoF.Up:
				offset = +2
			case ingress && !rp.infoF.Up:
				offset = +1
			case !ingress && rp.infoF.Up:
				offset = -1
			case !ingress && !rp.infoF.Up:
				offset = -2
			}
		case false:
			// Non-peer shortcut paths have an extra HOF above the last hop,
			// used for verification of the last hop in that segment.
			switch {
			case ingress && !rp.infoF.Up:
				offset = -1
			case !ingress && rp.infoF.Up:
				offset = +1
			}
		}
	}
	return rp.hopFVerFromRaw(offset)
}

// getHopFVerNormalOffset is a helper function for getHopFVer, to handle cases
// where the verification Hop Field (if any) is directly before or after
// (depending on the Up flag) the current Hop Field.
func (rp *RtrPkt) getHopFVerNormalOffset() int {
	iOff := int(rp.CmnHdr.CurrInfoF)
	hOff := int(rp.CmnHdr.CurrHopF)
	// If this is the last hop of an Up path, or the first hop of a Down path, there's no previous
	// HOF to verify against.
	if (rp.infoF.Up &&
		hOff == (iOff+spath.InfoFieldLength+int(rp.infoF.Hops-1)*spath.HopFieldLength)) ||
		(!rp.infoF.Up && hOff == (iOff+spath.InfoFieldLength)) {
		return 0
	}
	// Otherwise use the next/prev HOF based on the up flag.
	if rp.infoF.Up {
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
		b := rp.Raw[int(rp.CmnHdr.CurrHopF)+offset*common.LineLen:]
		copy(ans, b[1:common.LineLen])
	}
	return ans
}

// IncPath increments the packet's path, if any. The bool return value is set
// to true if the segment changes (specifically if the packet's metadata is
// updated to the new segment).
func (rp *RtrPkt) IncPath() (bool, *common.Error) {
	if rp.infoF == nil {
		// Path is empty, nothing to increment.
		return false, nil
	}
	if assert.On {
		assert.Must(rp.upFlag != nil, rp.ErrStr("rp.upFlag must not be nil"))
	}
	var err *common.Error
	var hopF *spath.HopField
	// Initialize to the current InfoF and offset values.
	infoF := rp.infoF
	iOff := rp.CmnHdr.CurrInfoF
	hOff := rp.CmnHdr.CurrHopF
	vOnly := 0
	origUp := *rp.upFlag
	for {
		hOff += spath.HopFieldLength
		if hOff-iOff > infoF.Hops*spath.HopFieldLength {
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
	if hOff > rp.CmnHdr.HdrLen {
		return false, common.NewError("New HopF offset > header length", "max", rp.CmnHdr.HdrLen,
			"actual", hOff)
	}
	// Update common header, and packet's InfoF/HopF fields.
	segChgd := iOff != rp.CmnHdr.CurrInfoF
	rp.CmnHdr.UpdatePathOffsets(rp.Raw, iOff, hOff)
	rp.infoF = infoF
	rp.hopF = hopF
	rp.IncrementedPath = true
	if segChgd {
		// Extract new Up flag.
		rp.upFlag = nil
		if _, err = rp.UpFlag(); err != nil {
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
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_BadHopField, rp.mkInfoPathOffsets())
		return segChgd, common.NewError("VERIFY_ONLY in middle of segment", sdata)
	}
	// Check that the segment didn't change from a down-segment to an up-segment.
	if !origUp && *rp.upFlag {
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_BadSegment, rp.mkInfoPathOffsets())
		return segChgd, common.NewError("Switched from down-segment to up-segment", sdata)
	}
	return segChgd, nil
}

// UpFlag retrieves the current path segment's Up flag if not already known.
// (Up is defined as being the opposite to the direction in which the segment
// was created.)
func (rp *RtrPkt) UpFlag() (*bool, *common.Error) {
	if rp.upFlag != nil {
		return rp.upFlag, nil
	}
	// Try to get Up flag from extensions
	for _, f := range rp.hooks.UpFlag {
		ret, up, err := f()
		switch {
		case err != nil:
			return nil, err
		case ret == HookContinue:
			continue
		case ret == HookFinish:
			rp.upFlag = &up
			return rp.upFlag, nil
		}
	}
	// Try to get Up flag from InfoField
	if rp.infoF == nil {
		return nil, nil
	}
	rp.upFlag = &rp.infoF.Up
	return rp.upFlag, nil
}

// IFCurr retrieves the current interface ID if not already known.
func (rp *RtrPkt) IFCurr() (*spath.IntfID, *common.Error) {
	if rp.ifCurr != nil {
		return rp.ifCurr, nil
	}
	if rp.upFlag != nil {
		// Try to get IFID from registered hooks.
		if ifid, err := rp.hookIF(*rp.upFlag, rp.hooks.IFCurr); err != nil {
			return nil, err
		} else if ifid != nil {
			return rp.checkSetCurrIF(ifid)
		}
		// Try to get IFID from HopField
		if rp.hopF != nil {
			var ingress bool
			switch rp.DirFrom {
			case DirSelf, DirLocal:
				ingress = *rp.upFlag
			case DirExternal:
				ingress = !*rp.upFlag
			default:
				return nil, common.NewError("DirFrom value unsupported", "val", rp.DirFrom)
			}
			if ingress {
				return rp.checkSetCurrIF(&rp.hopF.Ingress)
			}
			return rp.checkSetCurrIF(&rp.hopF.Egress)
		}
	}
	// Default to the first IfID from Ingress.IfIDs
	return rp.checkSetCurrIF(&rp.Ingress.IfIDs[0])
}

// checkSetCurrIF is a helper function that ensures the given interface ID is
// valid before setting the ifCurr field and returning the value.
func (rp *RtrPkt) checkSetCurrIF(ifid *spath.IntfID) (*spath.IntfID, *common.Error) {
	if ifid == nil {
		return nil, common.NewError("No interface found")
	}
	if _, ok := conf.C.Net.IFs[*ifid]; !ok {
		return nil, common.NewError("Unknown interface", "ifid", *ifid)
	}
	rp.ifCurr = ifid
	return rp.ifCurr, nil
}

// IFNext retrieves the next interface ID if not already known. As this may be
// an interface in an external ISD-AS, this is not sanity-checked.
func (rp *RtrPkt) IFNext() (*spath.IntfID, *common.Error) {
	if rp.ifNext == nil && rp.upFlag != nil {
		var err *common.Error
		// Try to get IFID from registered hooks.
		if rp.ifNext, err = rp.hookIF(*rp.upFlag, rp.hooks.IFNext); err != nil {
			return nil, err
		} else if rp.ifNext != nil {
			return rp.ifNext, nil
		}
		// Get IFID from HopField
		if *rp.upFlag {
			rp.ifNext = &rp.hopF.Ingress
		} else {
			rp.ifNext = &rp.hopF.Egress
		}
	}
	return rp.ifNext, nil
}

// hookIF is a helper function used by IFCurr/IFNext to run interface ID
// retrival hooks.
func (rp *RtrPkt) hookIF(up bool, hooks []hookIntf) (*spath.IntfID, *common.Error) {
	for _, f := range hooks {
		ret, intf, err := f(up, rp.DirFrom, rp.DirTo)
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
