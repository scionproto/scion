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
	"fmt"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/path"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/topology"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/proto"
)

const (
	ErrorProcessPldUnsupported = "Unable to process unsupported payload type"
	ErrorPldGet                = "Unable to retrieve payload"
	ErrorPCBWrongIF            = "Incorrect egress IFID in outgoing PCB"
	ErrorPCBWrongDir           = "Unsupported PCB DirFrom value"
)

func (p *Packet) NeedsLocalProcessing() *util.Error {
	if *p.dstIA != *conf.ia {
		// Packet isn't to this IA, so just forward.
		p.hooks.Route = append(p.hooks.Route, p.forward)
		return nil
	}
	if p.CmnHdr.DstType == addr.HostTypeSVC {
		if p.infoF == nil && len(p.idxs.hbhExt) == 0 {
			// To SVC address, no path - needs processing.
			p.hooks.Payload = append(p.hooks.Payload, p.parseCtrlPayload)
			p.hooks.Process = append(p.hooks.Process, p.processPathlessSVC)
		}
		// Resolve SVC address for delivery.
		p.hooks.Route = append(p.hooks.Route, p.RouteResolveSVC)
		return nil
	}
	dstIP := p.dstHost.IP()
	intf := conf.net.IFs[*p.ifCurr]
	extPub := intf.IFAddr.PublicAddr().IP
	locPub := conf.net.IntfLocalAddr(*p.ifCurr).PublicAddr().IP
	if p.DirFrom == DirExternal && extPub.Equal(dstIP) ||
		(p.DirFrom == DirLocal && locPub.Equal(dstIP)) {
		// Packet is meant for this router
		p.hooks.Payload = append(p.hooks.Payload, p.parseCtrlPayload)
		p.hooks.Process = append(p.hooks.Process, p.processDestSelf)
		return nil
	}
	// Normal packet to local AS, just forward.
	p.hooks.Route = append(p.hooks.Route, p.forward)
	return nil
}

// No fallback for process - a hook must be registered to read it.
func (p *Packet) Process() *util.Error {
	for _, f := range p.hooks.Process {
		ret, err := f()
		switch {
		case err != nil:
			return err
		case ret == HookContinue:
			continue
		case ret == HookFinish:
			break
		}
	}
	return nil
}

func (p *Packet) processPathlessSVC() (HookResult, *util.Error) {
	_, err := p.Payload()
	if err != nil {
		return HookError, err
	}
	pld, ok := p.pld.(*proto.SCION)
	if !ok {
		return HookError, util.NewError(ErrorProcessPldUnsupported,
			"pldType", fmt.Sprintf("%T", p.pld), "pld", p.pld)
	}
	switch pld.Which() {
	case proto.SCION_Which_ifid:
		ifid, err := pld.Ifid()
		if err != nil {
			return HookError, util.NewError(ErrorPldGet, "err", err)
		}
		return p.processIFID(ifid)
	case proto.SCION_Which_pcb:
		pcb, err := pld.Pcb()
		if err != nil {
			return HookError, util.NewError(ErrorPldGet, "err", err)
		}
		return p.processPCB(pcb)
	default:
		// TODO(kormat): when the other payloads are implemented, change this to an error.
		//return HookError, util.NewError("Unsupported payload type", "type", pld.Which())
		p.Warn("Unsupported payload type", "type", pld.Which())
		return HookContinue, nil
	}
}

func (p *Packet) processIFID(pld proto.IFID) (HookResult, *util.Error) {
	pld.SetRelayIF(uint16(*p.ifCurr))
	if err := p.updateCtrlPld(); err != nil {
		return HookError, err
	}
	return HookContinue, nil
}

func (p *Packet) processPCB(pld proto.PathSegment) (HookResult, *util.Error) {
	switch p.DirFrom {
	case DirExternal:
		pld.SetIfID(uint64(*p.ifCurr))
		if err := p.updateCtrlPld(); err != nil {
			return HookError, err
		}
	case DirLocal:
		rawH, err := pld.LastHopF()
		if err != nil {
			return HookError, err
		}
		hopF, err := path.HopFFromRaw(rawH)
		if err != nil {
			return HookError, err
		}
		if hopF.Egress != *p.ifCurr {
			return HookError, util.NewError(ErrorPCBWrongIF,
				log.Ctx{"expected": *p.ifCurr, "actual": hopF.Egress})
		}
	default:
		return HookError, util.NewError(ErrorPCBWrongDir, "DirFrom", p.DirFrom)
	}
	return HookContinue, nil
}

func (p *Packet) processDestSelf() (HookResult, *util.Error) {
	return HookContinue, nil
}

func getSVCNamesMap(svc addr.HostSVC) ([]string, map[string]topology.BasicElem) {
	var names []string
	var elemMap map[string]topology.BasicElem
	switch svc.Base() {
	case addr.SvcBS:
		names = conf.tm.BSNames
		elemMap = conf.tm.T.BS
	case addr.SvcPS:
		names = conf.tm.PSNames
		elemMap = conf.tm.T.PS
	case addr.SvcCS:
		names = conf.tm.CSNames
		elemMap = conf.tm.T.CS
	case addr.SvcSB:
		names = conf.tm.SBNames
		elemMap = conf.tm.T.SB
	}
	return names, elemMap
}
