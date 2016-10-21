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
	"fmt"

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/topology"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/proto"
)

const (
	ErrorProcessPldUnsupported = "Unable to process unsupported payload type"
	ErrorPldGet                = "Unable to retrieve payload"
)

func (p *Packet) NeedsLocalProcessing() *util.Error {
	if *p.dstIA != *conf.C.IA {
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
	intf := conf.C.Net.IFs[*p.ifCurr]
	extPub := intf.IFAddr.PublicAddr().IP
	locPub := conf.C.Net.IntfLocalAddr(*p.ifCurr).PublicAddr().IP
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
	default:
		return HookError, util.NewError("Unsupported payload type", "type", pld.Which())
	}
}

func (p *Packet) processDestSelf() (HookResult, *util.Error) {
	if _, err := p.Payload(); err != nil {
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
	case proto.SCION_Which_pathMgmt:
		pathMgmt, err := pld.PathMgmt()
		if err != nil {
			return HookError, util.NewError(ErrorPldGet, "err", err)
		}
		return p.processPathMgmtSelf(pathMgmt)
	default:
		p.Error("Unsupported destination payload", "type", pld.Which())
		return HookError, nil
	}
}

func (p *Packet) processIFID(pld proto.IFID) (HookResult, *util.Error) {
	pld.SetRelayIF(uint16(*p.ifCurr))
	if err := p.updateCtrlPld(); err != nil {
		return HookError, err
	}
	intf := conf.C.Net.IFs[*p.ifCurr]
	srcAddr := conf.C.Net.LocAddr[intf.LocAddrIdx].PublicAddr()
	// Create base packet
	pkt, err := CreateCtrlPacket(DirLocal, addr.HostFromIP(srcAddr.IP),
		conf.C.IA, addr.SvcBS.Multicast())
	if err != nil {
		p.Error("Error creating IFID forwarding packet", err.Ctx...)
	}
	pkt.AddL4UDP(srcAddr.Port, 0)
	// Set payload
	if err := pkt.AddCtrlPld(p.pld.(*proto.SCION)); err != nil {
		return HookError, util.NewError("Error setting IFID forwarding payload", err.Ctx...)
	}
	pkt.ifCurr = p.ifCurr
	_, err = pkt.RouteResolveSVC()
	if err != nil {
		p.Error("Error resolving SVC address", err.Ctx...)
		return HookError, nil
	}
	pkt.Route()
	return HookFinish, nil
}

func (p *Packet) processPathMgmtSelf(pathMgmt proto.PathMgmt) (HookResult, *util.Error) {
	switch pathMgmt.Which() {
	case proto.PathMgmt_Which_ifStateInfos:
		ifStates, err := pathMgmt.IfStateInfos()
		if err != nil {
			return HookError, util.NewError(ErrorPldGet, "err", err)
		}
		callbacks.ifStateUpd(ifStates)
	default:
		p.Error("Unsupported destination PathMgmt payload", "type", pathMgmt.Which())
		return HookError, nil
	}
	return HookFinish, nil
}

func (p *Packet) processSCMP() (HookResult, *util.Error) {
	// FIXME(kormat): rate-limit revocations
	hdr := p.l4.(*scmp.Hdr)
	switch {
	case hdr.Class == scmp.C_Path && hdr.Type == scmp.T_P_RevokedIF:
		pld := p.pld.(*scmp.Payload)
		callbacks.revTokenF(pld.Info.(*scmp.InfoRevocation).RevToken)
	}
	return HookFinish, nil
}

func getSVCNamesMap(svc addr.HostSVC) ([]string, map[string]topology.BasicElem) {
	var names []string
	var elemMap map[string]topology.BasicElem
	tm := conf.C.TopoMeta
	switch *svc.Base() {
	case addr.SvcBS:
		names = tm.BSNames
		elemMap = tm.T.BS
	case addr.SvcPS:
		names = tm.PSNames
		elemMap = tm.T.PS
	case addr.SvcCS:
		names = tm.CSNames
		elemMap = tm.T.CS
	case addr.SvcSB:
		names = tm.SBNames
		elemMap = tm.T.SB
	}
	return names, elemMap
}
