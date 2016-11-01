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
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/util"
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

func (rp *RPkt) validatePath(dirFrom Dir) *util.Error {
	if rp.infoF == nil || rp.hopF == nil {
		return nil
	}
	if rp.hopF.VerifyOnly {
		return util.NewError(ErrorHopFieldVerifyOnly)
	}
	hopfExpiry := rp.infoF.Timestamp().Add(
		time.Duration(rp.hopF.ExpTime) * spath.ExpTimeUnit * time.Second)
	if time.Now().After(hopfExpiry) {
		return util.NewError(ErrorHopFieldExpired, "expiry", hopfExpiry)
	}
	prevHopF, err := rp.getHopFVer(dirFrom)
	if err != nil {
		return err
	}
	return rp.hopF.Verify(conf.C.HFGenBlock, rp.infoF.TsInt, prevHopF)
}

func (rp *RPkt) InfoF() (*spath.InfoField, *util.Error) {
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
			return nil, util.NewError(ErrorGetInfoFTooSmall,
				"min", rp.idxs.path, "actual", rp.CmnHdr.CurrInfoF)
		case rp.CmnHdr.CurrInfoF > rp.CmnHdr.HdrLen:
			return nil, util.NewError(ErrorGetInfoFTooLarge,
				"max", rp.CmnHdr.HdrLen, "actual", rp.CmnHdr.CurrInfoF)
		case rp.CmnHdr.CurrInfoF < rp.CmnHdr.HdrLen:
			var err *util.Error
			if rp.infoF, err = spath.InfoFFromRaw(rp.Raw[rp.CmnHdr.CurrInfoF:]); err != nil {
				return nil, err
			}
		}
	}
	return rp.infoF, nil
}

func (rp *RPkt) HopF() (*spath.HopField, *util.Error) {
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
			return nil, util.NewError(ErrorGetHopFTooSmall,
				"min", rp.CmnHdr.CurrInfoF+spath.InfoFieldLength, "actual", rp.CmnHdr.CurrHopF)
		case rp.CmnHdr.CurrHopF < rp.CmnHdr.HdrLen:
			var err *util.Error
			if rp.hopF, err = spath.HopFFromRaw(rp.Raw[rp.CmnHdr.CurrHopF:]); err != nil {
				return nil, err
			}
		case rp.CmnHdr.CurrHopF > rp.CmnHdr.HdrLen:
			return nil, util.NewError(ErrorGetHopFTooLarge,
				"max", rp.CmnHdr.HdrLen, "actual", rp.CmnHdr.CurrHopF)
		}
	}
	return rp.hopF, nil
}

func (rp *RPkt) getHopFVer(dirFrom Dir) (util.RawBytes, *util.Error) {
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
	return rp.hopFVerFromRaw(offset), nil
}

func (rp *RPkt) getHopFVerNormalOffset() int {
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

func (rp *RPkt) hopFVerFromRaw(offset int) util.RawBytes {
	ans := make(util.RawBytes, common.LineLen-1)
	if offset != 0 {
		b := rp.Raw[int(rp.CmnHdr.CurrHopF)+offset*common.LineLen:]
		copy(ans, b[1:common.LineLen])
	}
	return ans
}

func (rp *RPkt) incPath() *util.Error {
	var err *util.Error
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
		return util.NewError("New HopF offset > header length", "max", rp.CmnHdr.HdrLen,
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

func (rp *RPkt) UpFlag() (*bool, *util.Error) {
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

func (rp *RPkt) IFCurr() (*spath.IntfID, *util.Error) {
	if rp.ifCurr != nil {
		return rp.ifCurr, nil
	}
	var err *util.Error
	if rp.upFlag != nil {
		// Try to get IFID from HopByHop extensions
		if rp.ifCurr, err = rp.hookIF(*rp.upFlag, rp.hooks.IFCurr); err != nil {
			return nil, err
		} else if rp.ifCurr != nil {
			return rp.ifCurr, nil
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
				return nil, util.NewError(ErrorDirFromUnsupported, "val", rp.DirFrom)
			}
			if ingress {
				rp.ifCurr = &rp.hopF.Ingress
			} else {
				rp.ifCurr = &rp.hopF.Egress
			}
			return rp.ifCurr, nil
		}
	}
	// Try to get IFID from Ingress.Dst
	addr := rp.Ingress.Dst.String()
	switch rp.DirFrom {
	case DirLocal:
		ifids, ok := conf.C.Net.LocAddrIFIDMap[addr]
		if !ok {
			return nil, util.NewError(ErrorLocAddrInvalid, "addr", addr)
		}
		// Just pick the first matching IFID
		rp.ifCurr = &ifids[0]
	case DirExternal:
		if ifid, ok := conf.C.Net.IFAddrMap[addr]; ok {
			rp.ifCurr = &ifid
		}
	default:
		return nil, util.NewError(ErrorDirFromUnsupported, "val", rp.DirFrom)
	}
	return rp.ifCurr, nil
}

func (rp *RPkt) IFNext() (*spath.IntfID, *util.Error) {
	if rp.ifNext == nil && rp.upFlag != nil {
		var err *util.Error
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

func (rp *RPkt) hookIF(up bool, hooks []HookIntf) (*spath.IntfID, *util.Error) {
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
