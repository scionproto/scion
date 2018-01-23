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

// This file handles packet processing.

package rpkt

import (
	"fmt"

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/ifstate"
	"github.com/netsec-ethz/scion/go/border/rcmn"
	"github.com/netsec-ethz/scion/go/border/rctx"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl"
	"github.com/netsec-ethz/scion/go/lib/ctrl/ifid"
	"github.com/netsec-ethz/scion/go/lib/ctrl/path_mgmt"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/topology"
)

const (
	errPldGet = "Unable to retrieve payload"
)

// NeedsLocalProcessing determines if the router needs to do more than just
// forward a packet (e.g. resolve an SVC destination address).
func (rp *RtrPkt) NeedsLocalProcessing() error {
	if *rp.dstIA != *rp.Ctx.Conf.IA {
		// Packet isn't to this ISD-AS, so just forward.
		rp.hooks.Route = append(rp.hooks.Route, rp.forward)
		return nil
	}
	if rp.CmnHdr.DstType == addr.HostTypeSVC {
		// SVC address needs to be resolved for delivery.
		rp.hooks.Route = append(rp.hooks.Route, rp.RouteResolveSVC)
		return nil
	}
	// Check to see if the destination IP is the address the packet was received
	// on.
	dstHost := addr.HostFromIP(rp.dstHost.IP())
	intf := rp.Ctx.Conf.Net.IFs[*rp.ifCurr]
	extPub := intf.IFAddr
	locPub := rp.Ctx.Conf.Net.IntfLocalAddr(*rp.ifCurr)
	if rp.DirFrom == rcmn.DirExternal {
		port, equal, err := extPub.PubL4PortFromAddr(dstHost)
		if err != nil {
			return err
		}
		if equal {
			return rp.isDestSelf(port)
		}
	} else if rp.DirFrom == rcmn.DirLocal {
		port, equal, err := locPub.PubL4PortFromAddr(dstHost)
		if err != nil {
			return err
		}
		if equal {
			return rp.isDestSelf(port)
		}
	}
	// Non-SVC packet to local AS, just forward.
	rp.hooks.Route = append(rp.hooks.Route, rp.forward)
	return nil
}

// isDestSelf checks if the packet's destination port (if any) matches the
// router's L4 port. If it does, hooks are registered to parse and process the
// payload. Otherwise it is forwarded to the local dispatcher.
func (rp *RtrPkt) isDestSelf(ownPort int) error {
	if _, err := rp.L4Hdr(true); err != nil {
		if err.(*common.CError).Desc != UnsupportedL4 {
			return err
		}
	}
	switch h := rp.l4.(type) {
	case *l4.UDP:
		if int(h.DstPort) == ownPort {
			goto Self
		}
	case *scmp.Hdr:
		// FIXME(kormat): this should really examine the SCMP header and
		// determine the real destination.
		goto Self
	}
	rp.DirTo = rcmn.DirLocal
	rp.hooks.Route = append(rp.hooks.Route, rp.forward)
	return nil
Self:
	rp.DirTo = rcmn.DirSelf
	rp.hooks.Payload = append(rp.hooks.Payload, rp.parseCtrlPayload)
	rp.hooks.Process = append(rp.hooks.Process, rp.processDestSelf)
	return nil
}

// Process uses any registered hooks to process the packet. Note that there is
// no generic fallback; if no hooks are registered, then no work is done.
func (rp *RtrPkt) Process() error {
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

// processDestSelf handles packets whose destination is this router. It
// determines the payload type, and dispatches the processing to the
// appropriate method.
func (rp *RtrPkt) processDestSelf() (HookResult, error) {
	if _, err := rp.Payload(true); err != nil {
		return HookError, err
	}
	cpld, ok := rp.pld.(*ctrl.Pld)
	if !ok {
		// FIXME(kormat): handle SCMP packets sent to this router.
		return HookError, common.NewCError("Unable to process unsupported payload type",
			"pldType", fmt.Sprintf("%T", rp.pld), "pld", rp.pld)
	}
	// Determine the type of SCION control payload.
	u, err := cpld.Union()
	if err != nil {
		return HookError, err
	}
	switch pld := u.(type) {
	case *ifid.IFID:
		return rp.processIFID(pld)
	case *path_mgmt.Pld:
		return rp.processPathMgmtSelf(pld)
	default:
		rp.Error("Unsupported destination payload", "type", common.TypeOf(pld))
		return HookError, nil
	}
}

// processIFID handles IFID (interface ID) packets from neighbouring ISD-ASes.
func (rp *RtrPkt) processIFID(ifid *ifid.IFID) (HookResult, error) {
	// Set the RelayIF field in the payload to the current interface ID.
	ifid.RelayIfID = uint64(*rp.ifCurr)
	cpld, err := ctrl.NewPld(ifid)
	if err != nil {
		return HookError, err
	}
	if err = rp.SetPld(cpld); err != nil {
		return HookError, err
	}
	intf := rp.Ctx.Conf.Net.IFs[*rp.ifCurr]
	srcAddr := rp.Ctx.Conf.Net.LocAddr[intf.LocAddrIdx].PublicAddrInfo(rp.Ctx.Conf.Topo.Overlay)
	// Create base packet to local beacon service (multicast).
	fwdrp, err := RtrPktFromScnPkt(&spkt.ScnPkt{
		DstIA: rp.Ctx.Conf.IA, SrcIA: rp.Ctx.Conf.IA,
		DstHost: addr.SvcBS.Multicast(), SrcHost: addr.HostFromIP(srcAddr.IP),
		L4: &l4.UDP{SrcPort: uint16(srcAddr.L4Port), DstPort: 0},
	}, rcmn.DirLocal, rp.Ctx)
	if err != nil {
		return HookError, err
	}
	// Use updated payload.
	if err := fwdrp.SetPld(rp.pld); err != nil {
		return HookError, common.NewCError("Error setting IFID forwarding payload", "err", err)
	}
	fwdrp.ifCurr = rp.ifCurr
	// Resolve SVC address.
	if _, err := fwdrp.RouteResolveSVC(); err != nil {
		return HookError, err
	}
	fwdrp.Route()
	return HookFinish, nil
}

// processPathMgmtSelf handles Path Management SCION control messages.
func (rp *RtrPkt) processPathMgmtSelf(p *path_mgmt.Pld) (HookResult, error) {
	u, err := p.Union()
	if err != nil {
		return HookError, err
	}
	switch pld := u.(type) {
	case *path_mgmt.IFStateInfos:
		ifstate.Process(pld)
	default:
		return HookError, common.NewCError("Unsupported destination PathMgmt payload",
			"type", common.TypeOf(pld))
	}
	return HookFinish, nil
}

// processSCMP is a processing hook used to handle SCMP payloads.
func (rp *RtrPkt) processSCMP() (HookResult, error) {
	// FIXME(shitz): rate-limit revocations
	hdr := rp.l4.(*scmp.Hdr)
	switch {
	case hdr.Class == scmp.C_Path && hdr.Type == scmp.T_P_RevokedIF:
		// Ignore any revocations received locally.
		if rp.DirFrom == rcmn.DirExternal {
			if err := rp.processSCMPRevocation(); err != nil {
				return HookError, err
			}
		}
	default:
		return HookError, common.NewCError("Unsupported destination SCMP payload",
			"class", hdr.Class, "type", hdr.Type.Name(hdr.Class))
	}
	return HookFinish, nil
}

// processSCMPRevocation handles SCMP revocations.
// There are 3 cases where the router does more than just forward an SCMP revocation message.
// 1. The revocation was received on a core interface, and the destination is in this ISD. In this
//    case the revocation is forked, and forwarded to the local BS and PS services. This prevents
//    the BS from propagating/registering revoked core PCBs. The destination check ensures that this
//    is only done for revocations which impact the local ISD.
// 2. The revocation was received from a parent AS, and the revoked interface is in the same ISD.
//    In this case the revocation is also forked to the local BS and PS services. This ensures that
//    ASes downstream of a revoked interface get informed quickly.
// 3. The revocation's destination is the local AS. The revocation notification is forked to the
//    local PS, to ensure that it stops providing segments with revoked interfaces to clients.
func (rp *RtrPkt) processSCMPRevocation() error {
	var args RevTokenCallbackArgs
	var err error
	pld, ok := rp.pld.(*scmp.Payload)
	if !ok {
		return common.NewCError("Invalid payload type in SCMP packet",
			"expected", "*scmp.Payload", "actual", common.TypeOf(rp.pld))
	}
	infoRev, ok := pld.Info.(*scmp.InfoRevocation)
	if !ok {
		return common.NewCError("Invalid SCMP Info type in SCMP packet",
			"expected", "*scmp.InfoRevocation", "actual", common.TypeOf(pld.Info))
	}
	if args.RevInfo, err = path_mgmt.NewRevInfoFromRaw(infoRev.RevToken); err != nil {
		return common.NewCError("Unable to decode revToken", "err", err)
	}
	intf := rp.Ctx.Conf.Net.IFs[*rp.ifCurr]
	rp.SrcIA() // Ensure that rp.srcIA has been set
	if (rp.dstIA.I == rp.Ctx.Conf.Topo.ISD_AS.I && intf.Type == topology.CoreLink) ||
		(rp.srcIA.I == rp.Ctx.Conf.Topo.ISD_AS.I && intf.Type == topology.ParentLink) {
		// Case 1 & 2
		args.Addrs = append(args.Addrs, addr.SvcBS)
		if len(rp.Ctx.Conf.Topo.PS) > 0 {
			args.Addrs = append(args.Addrs, addr.SvcPS)
		}
	} else if rp.dstIA.Eq(rp.Ctx.Conf.IA) && len(rp.Ctx.Conf.Topo.PS) > 0 {
		// Case 3
		args.Addrs = append(args.Addrs, addr.SvcPS)
	}
	if len(args.Addrs) > 0 {
		callbacks.revTokenF(args)
	}
	return nil
}

// getSVCNamesMap returns the slice of instance names and addresses for a given
// SVC address.
func getSVCNamesMap(svc addr.HostSVC, ctx *rctx.Ctx) (
	[]string, map[string]topology.TopoAddr, error) {
	t := ctx.Conf.Topo
	var names []string
	var elemMap map[string]topology.TopoAddr
	switch svc.Base() {
	case addr.SvcBS:
		names, elemMap = t.BSNames, t.BS
	case addr.SvcPS:
		names, elemMap = t.PSNames, t.PS
	case addr.SvcCS:
		names, elemMap = t.CSNames, t.CS
	case addr.SvcSB:
		names, elemMap = t.SBNames, t.SB
	default:
		sdata := scmp.NewErrData(scmp.C_Routing, scmp.T_R_BadHost, nil)
		return nil, nil, common.NewCErrorData("Unsupported SVC address", sdata, "svc", svc)
	}
	if len(elemMap) == 0 {
		sdata := scmp.NewErrData(scmp.C_Routing, scmp.T_R_UnreachHost, nil)
		return nil, nil, common.NewCErrorData(
			"No instances found for SVC address", sdata, "SVC", svc)
	}
	return names, elemMap, nil
}
