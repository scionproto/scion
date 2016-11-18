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

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/assert"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/spath"
)

const (
	ErrorHopFieldExpired    = "Hop field expired"
	ErrorHopFieldVerifyOnly = "Hop field is VERIFY_ONLY"
	ErrorGetInfoFTooSmall   = "Info field offset too small"
	ErrorGetInfoFTooLarge   = "Info field offset too large"
	ErrorGetHopFTooSmall    = "Hop field offset too small"
	ErrorGetHopFTooLarge    = "Hop field offset too large"
	ErrorDirFromUnsupported = "DirFrom value unsupported"
	ErrorLocAddrInvalid     = "Invalid local address"
)

func (rp *RtrPkt) validatePath(dirFrom Dir) *common.Error {
	if assert.On {
		assert.Must(rp.ifCurr != nil, rp.ErrStr("rp.ifCurr must not be nil"))
	}
	// First check to make sure the current interface is known and not revoked.
	if err := rp.validateLocalIF(*rp.ifCurr); err != nil {
		return err
	}
	// If there's no path, then there's nothing to check.
	if rp.infoF == nil || rp.hopF == nil {
		if rp.DirTo == DirSelf {
			// An empty path is legimate when the packet's destination is this router.
			return nil
		}
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_PathRequired, nil)
		return common.NewErrorData("Path required", sdata)
	}
	if rp.hopF.VerifyOnly {
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_NonRoutingHopF, rp.mkInfoPathOffsets())
		return common.NewErrorData(ErrorHopFieldVerifyOnly, sdata)
	}
	if rp.hopF.ForwardOnly && rp.dstIA == conf.C.IA {
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_DeliveryFwdOnly, rp.mkInfoPathOffsets())
		return common.NewErrorData(ErrorHopFieldVerifyOnly, sdata)
	}
	hopfExpiry := rp.infoF.Timestamp().Add(
		time.Duration(rp.hopF.ExpTime) * spath.ExpTimeUnit * time.Second)
	if time.Now().After(hopfExpiry) {
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_ExpiredHopF, rp.mkInfoPathOffsets())
		return common.NewErrorData(ErrorHopFieldExpired, sdata, "expiry", hopfExpiry)
	}
	err := rp.hopF.Verify(conf.C.HFGenBlock, rp.infoF.TsInt, rp.getHopFVer(dirFrom))
	if err != nil && err.Desc == spath.ErrorHopFBadMac {
		err.Data = scmp.NewErrData(scmp.C_Path, scmp.T_P_BadMac, rp.mkInfoPathOffsets())
	}
	return err
}

func (rp *RtrPkt) validateLocalIF(ifid spath.IntfID) *common.Error {
	if _, ok := conf.C.TopoMeta.IFMap[int(ifid)]; !ok {
		// No such interface.
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_BadIF, rp.mkInfoPathOffsets())
		return common.NewErrorData("Unknown IF", sdata, "ifid", ifid)
	}
	conf.C.IFStates.RLock()
	info, ok := conf.C.IFStates.M[ifid]
	conf.C.IFStates.RUnlock()
	if !ok || info.P.Active() || rp.DirTo == DirSelf {
		// Either the interface isn't revoked, or the packet is to this
		// router, in which case revocations are ignored to allow communication
		// with the router.
		return nil
	}
	// Interface is revoked.
	sinfo := scmp.NewInfoRevocation(
		uint16(rp.CmnHdr.CurrInfoF), uint16(rp.CmnHdr.CurrHopF), uint16(ifid),
		rp.DirFrom == DirExternal, info.RawRev)
	sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_RevokedIF, sinfo)
	return common.NewErrorData(ErrorIntfRevoked, sdata, "ifid", ifid)
}

func (rp *RtrPkt) mkInfoPathOffsets() scmp.Info {
	return &scmp.InfoPathOffsets{
		InfoF: uint16(rp.CmnHdr.CurrInfoF), HopF: uint16(rp.CmnHdr.CurrHopF),
		IfID: uint16(*rp.ifCurr), Ingress: rp.DirFrom == DirExternal,
	}
}

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
		switch {
		case int(rp.CmnHdr.CurrInfoF) < rp.idxs.path:
			sdata := scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadInfoFOffset, nil)
			return nil, common.NewErrorData(ErrorGetInfoFTooSmall, sdata,
				"min", rp.idxs.path, "actual", rp.CmnHdr.CurrInfoF)
		case rp.CmnHdr.CurrInfoF > rp.CmnHdr.HdrLen:
			sdata := scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadInfoFOffset, nil)
			return nil, common.NewErrorData(ErrorGetInfoFTooLarge, sdata,
				"max", rp.CmnHdr.HdrLen, "actual", rp.CmnHdr.CurrInfoF)
		case rp.CmnHdr.CurrInfoF < rp.CmnHdr.HdrLen:
			var err *common.Error
			if rp.infoF, err = spath.InfoFFromRaw(rp.Raw[rp.CmnHdr.CurrInfoF:]); err != nil {
				return nil, err
			}
		}
	}
	return rp.infoF, nil
}

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
		switch {
		case rp.CmnHdr.CurrHopF == rp.CmnHdr.CurrInfoF:
			// Do nothing
		case rp.CmnHdr.CurrHopF < rp.CmnHdr.CurrInfoF+spath.InfoFieldLength:
			sdata := scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadHopFOffset, nil)
			return nil, common.NewErrorData(ErrorGetHopFTooSmall, sdata,
				"min", rp.CmnHdr.CurrInfoF+spath.InfoFieldLength, "actual", rp.CmnHdr.CurrHopF)
		case rp.CmnHdr.CurrHopF < rp.CmnHdr.HdrLen:
			var err *common.Error
			if rp.hopF, err = spath.HopFFromRaw(rp.Raw[rp.CmnHdr.CurrHopF:]); err != nil {
				return nil, err
			}
		case rp.CmnHdr.CurrHopF >= rp.CmnHdr.HdrLen:
			sdata := scmp.NewErrData(scmp.C_CmnHdr, scmp.T_C_BadHopFOffset, nil)
			return nil, common.NewErrorData(ErrorGetHopFTooLarge, sdata,
				"max", rp.CmnHdr.HdrLen-spath.HopFieldLength, "actual", rp.CmnHdr.CurrHopF)
		}
	}
	return rp.hopF, nil
}

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

func (rp *RtrPkt) getHopFVerNormalOffset() int {
	// If this is the last hop of an Up path, or the first hop of a Down path,
	// there's no previous HOF to verify against.
	iOff := int(rp.CmnHdr.CurrInfoF)
	hOff := int(rp.CmnHdr.CurrHopF)
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

func (rp *RtrPkt) hopFVerFromRaw(offset int) common.RawBytes {
	ans := make(common.RawBytes, common.LineLen-1)
	if offset != 0 {
		b := rp.Raw[int(rp.CmnHdr.CurrHopF)+offset*common.LineLen:]
		copy(ans, b[1:common.LineLen])
	}
	return ans
}

func (rp *RtrPkt) IncPath() *common.Error {
	if rp.infoF == nil {
		// Path is empty, nothing to increment.
		return nil
	}
	var err *common.Error
	var hopF *spath.HopField
	infoF := rp.infoF
	iOff := rp.CmnHdr.CurrInfoF
	hOff := rp.CmnHdr.CurrHopF
	for {
		hOff += spath.HopFieldLength
		if hOff-iOff > infoF.Hops*spath.HopFieldLength {
			// Switch to next segment
			iOff = hOff
			if infoF, err = spath.InfoFFromRaw(rp.Raw[iOff:]); err != nil {
				return err
			}
			continue
		}
		if hopF, err = spath.HopFFromRaw(rp.Raw[hOff:]); err != nil {
			return err
		}
		if !hopF.VerifyOnly {
			break
		}
	}
	if hOff > rp.CmnHdr.HdrLen {
		return common.NewError("New HopF offset > header length", "max", rp.CmnHdr.HdrLen,
			"actual", hOff)
	}
	rp.CmnHdr.UpdatePathOffsets(rp.Raw, iOff, hOff)
	rp.infoF = infoF
	rp.hopF = hopF
	rp.upFlag = nil
	if _, err = rp.UpFlag(); err != nil {
		return err
	}
	rp.ifNext = nil
	if _, err = rp.IFNext(); err != nil {
		return err
	}
	return nil
}

func (rp *RtrPkt) UpFlag() (*bool, *common.Error) {
	if rp.upFlag != nil {
		return rp.upFlag, nil
	}
	// Try to get up flag from extensions
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
	// Try to get from InfoField
	if rp.infoF == nil {
		return nil, nil
	}
	rp.upFlag = &rp.infoF.Up
	return rp.upFlag, nil
}

func (rp *RtrPkt) IFCurr() (*spath.IntfID, *common.Error) {
	if rp.ifCurr != nil {
		return rp.ifCurr, nil
	}
	if rp.upFlag != nil {
		// Try to get IFID from HopByHop extensions
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
				return nil, common.NewError(ErrorDirFromUnsupported, "val", rp.DirFrom)
			}
			if ingress {
				return rp.checkSetCurrIF(&rp.hopF.Ingress)
			}
			return rp.checkSetCurrIF(&rp.hopF.Egress)
		}
	}
	// Use first IfID from Ingress.IfIDs
	return rp.checkSetCurrIF(&rp.Ingress.IfIDs[0])
}

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

func (rp *RtrPkt) IFNext() (*spath.IntfID, *common.Error) {
	if rp.ifNext == nil && rp.upFlag != nil {
		var err *common.Error
		if rp.ifNext, err = rp.hookIF(*rp.upFlag, rp.hooks.IFNext); err != nil {
			return nil, err
		} else if rp.ifNext != nil {
			return rp.ifNext, nil
		}
		if *rp.upFlag {
			rp.ifNext = &rp.hopF.Ingress
		} else {
			rp.ifNext = &rp.hopF.Egress
		}
	}
	return rp.ifNext, nil
}

func (rp *RtrPkt) hookIF(up bool, hooks []HookIntf) (*spath.IntfID, *common.Error) {
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
