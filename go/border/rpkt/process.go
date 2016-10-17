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
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/topology"
	"github.com/netsec-ethz/scion/go/proto"
)

const (
	ErrorProcessPldUnsupported = "Unable to process unsupported payload type"
	ErrorPldGet                = "Unable to retrieve payload"
)

func (rp *RtrPkt) NeedsLocalProcessing() *common.Error {
	if *rp.dstIA != *conf.C.IA {
		// Packet isn't to this IA, so just forward.
		rp.hooks.Route = append(rp.hooks.Route, rp.forward)
		return nil
	}
	if rp.CmnHdr.DstType == addr.HostTypeSVC {
		// Resolve SVC address for delivery.
		rp.hooks.Route = append(rp.hooks.Route, rp.RouteResolveSVC)
		return nil
	}
	dstIP := rp.dstHost.IP()
	intf := conf.C.Net.IFs[*rp.ifCurr]
	extPub := intf.IFAddr.PublicAddr().IP
	locPub := conf.C.Net.IntfLocalAddr(*rp.ifCurr).PublicAddr().IP
	if rp.DirFrom == DirExternal && extPub.Equal(dstIP) ||
		(rp.DirFrom == DirLocal && locPub.Equal(dstIP)) {
		// Packet is meant for this router
		rp.DirTo = DirSelf
		rp.hooks.Payload = append(rp.hooks.Payload, rp.parseCtrlPayload)
		rp.hooks.Process = append(rp.hooks.Process, rp.processDestSelf)
		return nil
	}
	// Normal packet to local AS, just forward.
	rp.hooks.Route = append(rp.hooks.Route, rp.forward)
	return nil
}

// No fallback for process - a hook must be registered to read it.
func (rp *RtrPkt) Process() *common.Error {
	for _, f := range rp.hooks.Process {
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

func (rp *RtrPkt) processDestSelf() (HookResult, *common.Error) {
	if _, err := rp.Payload(true); err != nil {
		return HookError, err
	}
	cpld, ok := rp.pld.(*spkt.CtrlPld)
	if !ok {
		return HookError, common.NewError(ErrorProcessPldUnsupported,
			"pldType", fmt.Sprintf("%T", rp.pld), "pld", rp.pld)
	}
	pld := cpld.SCION
	switch pld.Which() {
	case proto.SCION_Which_ifid:
		ifid, err := pld.Ifid()
		if err != nil {
			return HookError, common.NewError(ErrorPldGet, "err", err)
		}
		return rp.processIFID(ifid)
	case proto.SCION_Which_pathMgmt:
		pathMgmt, err := pld.PathMgmt()
		if err != nil {
			return HookError, common.NewError(ErrorPldGet, "err", err)
		}
		return rp.processPathMgmtSelf(pathMgmt)
	default:
		rp.Error("Unsupported destination payload", "type", pld.Which())
		return HookError, nil
	}
}

func (rp *RtrPkt) processIFID(pld proto.IFID) (HookResult, *common.Error) {
	pld.SetRelayIF(uint16(*rp.ifCurr))
	if err := rp.SetPld(rp.pld); err != nil {
		return HookError, err
	}
	intf := conf.C.Net.IFs[*rp.ifCurr]
	srcAddr := conf.C.Net.LocAddr[intf.LocAddrIdx].PublicAddr()
	// Create base packet
	fwdrp, err := RtrPktFromScnPkt(&spkt.ScnPkt{
		SrcIA: conf.C.IA, SrcHost: addr.HostFromIP(srcAddr.IP),
		DstIA: conf.C.IA, DstHost: addr.SvcBS.Multicast(),
		L4: &l4.UDP{SrcPort: uint16(srcAddr.Port), DstPort: 0},
	}, DirLocal)
	if err != nil {
		return HookError, err
	}
	// Set payload
	if err := fwdrp.SetPld(rp.pld); err != nil {
		return HookError, common.NewError("Error setting IFID forwarding payload", err.Ctx...)
	}
	fwdrp.ifCurr = rp.ifCurr
	if _, err := fwdrp.RouteResolveSVC(); err != nil {
		return HookError, err
	}
	fwdrp.Route()
	return HookFinish, nil
}

func (rp *RtrPkt) processPathMgmtSelf(pathMgmt proto.PathMgmt) (HookResult, *common.Error) {
	switch pathMgmt.Which() {
	case proto.PathMgmt_Which_ifStateInfos:
		ifStates, err := pathMgmt.IfStateInfos()
		if err != nil {
			return HookError, common.NewError(ErrorPldGet, "err", err)
		}
		callbacks.ifStateUpd(ifStates)
	default:
		rp.Error("Unsupported destination PathMgmt payload", "type", pathMgmt.Which())
		return HookError, nil
	}
	return HookFinish, nil
}

func (rp *RtrPkt) processSCMP() (HookResult, *common.Error) {
	// FIXME(kormat): rate-limit revocations
	hdr := rp.l4.(*scmp.Hdr)
	switch {
	case hdr.Class == scmp.C_Path && hdr.Type == scmp.T_P_RevokedIF:
		pld := rp.pld.(*scmp.Payload)
		callbacks.revTokenF(pld.Info.(*scmp.InfoRevocation).RevToken)
	}
	return HookFinish, nil
}

func getSVCNamesMap(svc addr.HostSVC) ([]string, map[string]topology.BasicElem, *common.Error) {
	tm := conf.C.TopoMeta
	var names []string
	var elemMap map[string]topology.BasicElem
	switch svc.Base() {
	case addr.SvcBS:
		names, elemMap = tm.BSNames, tm.T.BS
	case addr.SvcPS:
		names, elemMap = tm.PSNames, tm.T.PS
	case addr.SvcCS:
		names, elemMap = tm.CSNames, tm.T.CS
	case addr.SvcSB:
		names, elemMap = tm.SBNames, tm.T.SB
	default:
		sdata := scmp.NewErrData(scmp.C_Routing, scmp.T_R_BadHost, nil)
		return nil, nil, common.NewErrorData("Unsupported SVC address", sdata, "svc", svc)
	}
	if len(elemMap) == 0 {
		sdata := scmp.NewErrData(scmp.C_Routing, scmp.T_R_UnreachHost, nil)
		return nil, nil, common.NewErrorData(
			"No instances found for SVC address", sdata, "svc", svc)
	}
	return names, elemMap, nil
}
