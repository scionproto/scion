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

package packet

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

func (p *Packet) validatePath(dirFrom Dir) *util.Error {
	if p.infoF == nil || p.hopF == nil {
		return nil
	}
	if p.hopF.VerifyOnly {
		return util.NewError(ErrorHopFieldVerifyOnly)
	}
	hopfExpiry := p.infoF.Timestamp().Add(
		time.Duration(p.hopF.ExpTime) * spath.ExpTimeUnit * time.Second)
	if time.Now().After(hopfExpiry) {
		return util.NewError(ErrorHopFieldExpired, "expiry", hopfExpiry)
	}
	prevHopF, err := p.getHopFVer(dirFrom)
	if err != nil {
		return err
	}
	return p.hopF.Verify(conf.C.HFGenBlock, p.infoF.TsInt, prevHopF)
}

func (p *Packet) InfoF() (*spath.InfoField, *util.Error) {
	if p.infoF == nil {
		for _, f := range p.hooks.Infof {
			ret, infof, err := f()
			switch {
			case err != nil:
				return nil, err
			case ret == HookContinue:
				continue
			case ret == HookFinish:
				p.infoF = infof
				return p.infoF, nil
			}
		}
		switch {
		case int(p.CmnHdr.CurrInfoF) < p.idxs.path:
			return nil, util.NewError(ErrorGetInfoFTooSmall,
				"min", p.idxs.path, "actual", p.CmnHdr.CurrInfoF)
		case p.CmnHdr.CurrInfoF > p.CmnHdr.HdrLen:
			return nil, util.NewError(ErrorGetInfoFTooLarge,
				"max", p.CmnHdr.HdrLen, "actual", p.CmnHdr.CurrInfoF)
		case p.CmnHdr.CurrInfoF < p.CmnHdr.HdrLen:
			var err *util.Error
			if p.infoF, err = spath.InfoFFromRaw(p.Raw[p.CmnHdr.CurrInfoF:]); err != nil {
				return nil, err
			}
		}
	}
	return p.infoF, nil
}

func (p *Packet) HopF() (*spath.HopField, *util.Error) {
	if p.hopF == nil {
		for _, f := range p.hooks.HopF {
			ret, hopf, err := f()
			switch {
			case err != nil:
				return nil, err
			case ret == HookContinue:
				continue
			case ret == HookFinish:
				p.hopF = hopf
				return p.hopF, nil
			}
		}
		switch {
		case p.CmnHdr.CurrHopF == p.CmnHdr.CurrInfoF:
			// Do nothing
		case p.CmnHdr.CurrHopF < p.CmnHdr.CurrInfoF+spath.InfoFieldLength:
			return nil, util.NewError(ErrorGetHopFTooSmall,
				"min", p.CmnHdr.CurrInfoF+spath.InfoFieldLength, "actual", p.CmnHdr.CurrHopF)
		case p.CmnHdr.CurrHopF < p.CmnHdr.HdrLen:
			var err *util.Error
			if p.hopF, err = spath.HopFFromRaw(p.Raw[p.CmnHdr.CurrHopF:]); err != nil {
				return nil, err
			}
		case p.CmnHdr.CurrHopF > p.CmnHdr.HdrLen:
			return nil, util.NewError(ErrorGetHopFTooLarge,
				"max", p.CmnHdr.HdrLen, "actual", p.CmnHdr.CurrHopF)
		}
	}
	return p.hopF, nil
}

func (p *Packet) getHopFVer(dirFrom Dir) (util.RawBytes, *util.Error) {
	ingress := dirFrom == DirExternal
	var offset int
	if !p.hopF.Xover || (p.infoF.Shortcut && !p.infoF.Peer) {
		offset = p.getHopFVerNormalOffset()
	} else {
		switch p.infoF.Peer {
		case true:
			// Peer shortcut paths have two extra HOFs; 1 for the peering
			// interface, and another from the upstream interface, used for
			// verification only.
			switch {
			case ingress && p.infoF.Up:
				offset = +2
			case ingress && !p.infoF.Up:
				offset = +1
			case !ingress && p.infoF.Up:
				offset = -1
			case !ingress && !p.infoF.Up:
				offset = -2
			}
		case false:
			// Non-peer shortcut paths have an extra HOF above the last hop,
			// used for verification of the last hop in that segment.
			switch {
			case ingress && !p.infoF.Up:
				offset = -1
			case !ingress && p.infoF.Up:
				offset = +1
			}
		}
	}
	return p.hopFVerFromRaw(offset), nil
}

func (p *Packet) getHopFVerNormalOffset() int {
	// If this is the last hop of an Up path, or the first hop of a Down path,
	// there's no previous HOF to verify against.
	iOff := int(p.CmnHdr.CurrInfoF)
	hOff := int(p.CmnHdr.CurrHopF)
	if (p.infoF.Up &&
		hOff == (iOff+spath.InfoFieldLength+int(p.infoF.Hops-1)*spath.HopFieldLength)) ||
		(!p.infoF.Up && hOff == (iOff+spath.InfoFieldLength)) {
		return 0
	}
	// Otherwise use the next/prev HOF based on the up flag.
	if p.infoF.Up {
		return 1
	}
	return -1
}

func (p *Packet) hopFVerFromRaw(offset int) util.RawBytes {
	ans := make(util.RawBytes, common.LineLen-1)
	if offset != 0 {
		b := p.Raw[int(p.CmnHdr.CurrHopF)+offset*common.LineLen:]
		copy(ans, b[1:common.LineLen])
	}
	return ans
}

func (p *Packet) incPath() *util.Error {
	var err *util.Error
	var hopF *spath.HopField
	infoF := p.infoF
	iOff := p.CmnHdr.CurrInfoF
	hOff := p.CmnHdr.CurrHopF
	for {
		hOff += spath.HopFieldLength
		if hOff-iOff > infoF.Hops*spath.HopFieldLength {
			// Switch to next segment
			iOff = hOff
			if infoF, err = spath.InfoFFromRaw(p.Raw[iOff:]); err != nil {
				return err
			}
			continue
		}
		if hopF, err = spath.HopFFromRaw(p.Raw[hOff:]); err != nil {
			return err
		}
		if !hopF.VerifyOnly {
			break
		}
	}
	if hOff > p.CmnHdr.HdrLen {
		return util.NewError("New HopF offset > header length", "max", p.CmnHdr.HdrLen,
			"actual", hOff)
	}
	p.CmnHdr.UpdatePathOffsets(p.Raw, iOff, hOff)
	p.infoF = infoF
	p.hopF = hopF
	p.upFlag = nil
	if _, err = p.UpFlag(); err != nil {
		return err
	}
	p.ifNext = nil
	if _, err = p.IFNext(); err != nil {
		return err
	}
	return nil
}

func (p *Packet) UpFlag() (*bool, *util.Error) {
	if p.upFlag != nil {
		return p.upFlag, nil
	}
	// Try to get up flag from extensions
	for _, f := range p.hooks.UpFlag {
		ret, up, err := f()
		switch {
		case err != nil:
			return nil, err
		case ret == HookContinue:
			continue
		case ret == HookFinish:
			p.upFlag = &up
			return p.upFlag, nil
		}
	}
	// Try to get from InfoField
	if p.infoF == nil {
		return nil, nil
	}
	p.upFlag = &p.infoF.Up
	return p.upFlag, nil
}

func (p *Packet) IFCurr() (*spath.IntfID, *util.Error) {
	if p.ifCurr != nil {
		return p.ifCurr, nil
	}
	var err *util.Error
	if p.upFlag != nil {
		// Try to get IFID from HopByHop extensions
		if p.ifCurr, err = p.hookIF(*p.upFlag, p.hooks.IFCurr); err != nil {
			return nil, err
		} else if p.ifCurr != nil {
			return p.ifCurr, nil
		}
		// Try to get IFID from HopField
		if p.hopF != nil {
			var ingress bool
			switch p.DirFrom {
			case DirSelf, DirLocal:
				ingress = *p.upFlag
			case DirExternal:
				ingress = !*p.upFlag
			default:
				return nil, util.NewError(ErrorDirFromUnsupported, "val", p.DirFrom)
			}
			if ingress {
				p.ifCurr = &p.hopF.Ingress
			} else {
				p.ifCurr = &p.hopF.Egress
			}
			return p.ifCurr, nil
		}
	}
	// Try to get IFID from Ingress.Dst
	addr := p.Ingress.Dst.String()
	switch p.DirFrom {
	case DirLocal:
		ifids, ok := conf.C.Net.LocAddrIFIDMap[addr]
		if !ok {
			return nil, util.NewError(ErrorLocAddrInvalid, "addr", addr)
		}
		// Just pick the first matching IFID
		p.ifCurr = &ifids[0]
	case DirExternal:
		if ifid, ok := conf.C.Net.IFAddrMap[addr]; ok {
			p.ifCurr = &ifid
		}
	default:
		return nil, util.NewError(ErrorDirFromUnsupported, "val", p.DirFrom)
	}
	return p.ifCurr, nil
}

func (p *Packet) IFNext() (*spath.IntfID, *util.Error) {
	if p.ifNext == nil && p.upFlag != nil {
		var err *util.Error
		if p.ifNext, err = p.hookIF(*p.upFlag, p.hooks.IFNext); err != nil {
			return nil, err
		} else if p.ifNext != nil {
			return p.ifNext, nil
		}
		if *p.upFlag {
			p.ifNext = &p.hopF.Ingress
		} else {
			p.ifNext = &p.hopF.Egress
		}
	}
	return p.ifNext, nil
}

func (p *Packet) hookIF(up bool, hooks []HookIntf) (*spath.IntfID, *util.Error) {
	for _, f := range hooks {
		ret, intf, err := f(up, p.DirFrom, p.DirTo)
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
