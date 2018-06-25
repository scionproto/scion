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
	"time"

	"github.com/scionproto/scion/go/border/ifstate"
	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ifid"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	errPldGet = "Unable to retrieve payload"
)

type IFIDCallbackArgs struct {
	RtrPkt *RtrPkt
	IfID   common.IFIDType
}

// NeedsLocalProcessing determines if the router needs to do more than just
// forward a packet (e.g. resolve an SVC destination address).
func (rp *RtrPkt) NeedsLocalProcessing() error {
	if !rp.dstIA.Eq(rp.Ctx.Conf.IA) {
		// Packet isn't to this ISD-AS, so just forward.
		rp.hooks.Route = append(rp.hooks.Route, rp.forward)
		return nil
	}
	if rp.CmnHdr.DstType == addr.HostTypeSVC {
		// SVC address needs to be resolved for delivery.
		rp.hooks.Route = append(rp.hooks.Route, rp.RouteResolveSVC)
		return nil
	}
	// Check to see if the destination IP is the address the packet was received on.
	if rp.DirTo == rcmn.DirSelf {
		return rp.isDestSelf(rp.Ingress.Dst.L4Port)
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
		if common.GetErrorMsg(err) != UnsupportedL4 {
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
	// Forward to dispatcher in local host
	rp.DirTo = rcmn.DirLocal
	rp.hooks.Route = append(rp.hooks.Route, rp.forward)
	return nil
Self:
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
		return HookError, common.NewBasicError("Unable to process unsupported payload type", nil,
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

// processIFID handles IFID (interface ID) packets
func (rp *RtrPkt) processIFID(ifid *ifid.IFID) (HookResult, error) {
	if rp.DirFrom == rcmn.DirLocal {
		callbacks.ifIDF(IFIDCallbackArgs{RtrPkt: rp, IfID: ifid.OrigIfID})
		return HookFinish, nil
	} else {
		return rp.processRemoteIFID(ifid)
	}
}

// processRemoteIFID handles IFID (interface ID) packets from neighbouring ISD-ASes.
func (rp *RtrPkt) processRemoteIFID(ifid *ifid.IFID) (HookResult, error) {
	// Set the RelayIF field in the payload to the current interface ID.
	ifid.RelayIfID = rp.Ingress.IfID
	cpld, err := ctrl.NewPld(ifid, nil)
	if err != nil {
		return HookError, err
	}
	scpld, err := cpld.SignedPld(ctrl.NullSigner)
	if err != nil {
		return HookError, err
	}
	if err = rp.SetPld(scpld); err != nil {
		return HookError, err
	}
	srcAddr := rp.Ctx.Conf.Net.LocAddr.PublicAddrInfo(rp.Ctx.Conf.Topo.Overlay)
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
		return HookError, common.NewBasicError("Error setting IFID forwarding payload", err)
	}
	fwdrp.ifCurr = rp.ifCurr
	// Resolve SVC address.
	if _, err := fwdrp.RouteResolveSVC(); err != nil {
		return HookError, err
	}
	fwdrp.Route()
	return HookContinue, nil
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
		return HookError, common.NewBasicError("Unsupported destination PathMgmt payload", nil,
			"type", common.TypeOf(pld))
	}
	return HookContinue, nil
}

// processSCMP is a processing hook used to handle SCMP payloads.
func (rp *RtrPkt) processSCMP() (HookResult, error) {
	// FIXME(shitz): rate-limit revocations
	hdr := rp.l4.(*scmp.Hdr)
	switch {
	case hdr.Class == scmp.C_General && hdr.Type == scmp.T_G_TraceRouteRequest:
		if err := rp.processSCMPTraceRoute(); err != nil {
			return HookError, err
		}
	case hdr.Class == scmp.C_General && hdr.Type == scmp.T_G_RecordPathRequest:
		if err := rp.processSCMPRecordPath(); err != nil {
			return HookError, err
		}
	case hdr.Class == scmp.C_Path && hdr.Type == scmp.T_P_RevokedIF:
		// Ignore any revocations received locally.
		if rp.DirFrom == rcmn.DirExternal {
			if err := rp.processSCMPRevocation(); err != nil {
				return HookError, err
			}
		}
	default:
		return HookError, common.NewBasicError("Unsupported destination SCMP payload", nil,
			"class", hdr.Class, "type", hdr.Type.Name(hdr.Class))
	}
	return HookContinue, nil
}

func (rp *RtrPkt) processSCMPTraceRoute() error {
	pld, ok := rp.pld.(*scmp.Payload)
	if !ok {
		return common.NewBasicError("Invalid payload type in SCMP packet", nil,
			"expected", "*scmp.Payload", "actual", common.TypeOf(rp.pld))
	}
	infoTrace, ok := pld.Info.(*scmp.InfoTraceRoute)
	if !ok {
		return common.NewBasicError("Invalid SCMP Info type in SCMP packet", nil,
			"expected", "*scmp.InfoTraceRoute", "actual", common.TypeOf(pld.Info))
	}
	if infoTrace.HopOff != rp.CmnHdr.CurrHopF {
		return nil
	}
	// If In is set and the packet came from the local AS,
	// or if In is false and the packet came from outside,
	// then stop processing.
	if infoTrace.In != (rp.DirFrom == rcmn.DirExternal) {
		return nil
	}
	infoTrace.IA = rp.Ctx.Conf.IA
	infoTrace.IfID = *rp.ifCurr
	// Create generic ScnPkt reply
	sp, err := rp.CreateReplyScnPkt()
	if err != nil {
		return err
	}
	// Reply does not need to be HBH, so remove SCMP ext
	sp.HBHExt = sp.HBHExt[1:]
	scmpHdr := sp.L4.(*scmp.Hdr)
	scmpHdr.Type = scmp.T_G_TraceRouteReply

	reply, err := rp.CreateReply(sp)
	if err != nil {
		return err
	}
	reply.Route()
	// Change direction of current packet so it is not forwarded
	rp.DirTo = rcmn.DirSelf
	return nil
}

func (rp *RtrPkt) processSCMPRecordPath() error {
	pld, ok := rp.pld.(*scmp.Payload)
	if !ok {
		return common.NewBasicError("Invalid payload type in SCMP packet", nil,
			"expected", "*scmp.Payload", "actual", common.TypeOf(rp.pld))
	}
	infoRec, ok := pld.Info.(*scmp.InfoRecordPath)
	if !ok {
		return common.NewBasicError("Invalid SCMP Info type in SCMP packet", nil,
			"expected", "*scmp.InfoRecordPath", "actual", common.TypeOf(pld.Info))
	}
	// Calculate time in microseconds since scmp packet was created
	hdr := rp.l4.(*scmp.Hdr)
	ts := uint32(time.Since(hdr.Time()) / time.Microsecond)
	entry := &scmp.RecordPathEntry{
		IA: rp.Ctx.Conf.IA, TS: ts, IfID: *rp.ifCurr,
	}
	infoRec.Entries = append(infoRec.Entries, entry)
	info := rp.Raw[rp.idxs.pld+scmp.MetaLen:]
	if _, err := infoRec.Write(info); err != nil {
		return common.NewBasicError("Unable to add path entry to SCMP Record Path packet",
			nil, "err", err)
	}
	if err := rp.updateL4(); err != nil {
		return common.NewBasicError("Failed to update L4 header", nil, "err", err)
	}
	return nil
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
	var args RawSRevCallbackArgs
	var err error
	pld, ok := rp.pld.(*scmp.Payload)
	if !ok {
		return common.NewBasicError("Invalid payload type in SCMP packet", nil,
			"expected", "*scmp.Payload", "actual", common.TypeOf(rp.pld))
	}
	infoRev, ok := pld.Info.(*scmp.InfoRevocation)
	if !ok {
		return common.NewBasicError("Invalid SCMP Info type in SCMP packet", nil,
			"expected", "*scmp.InfoRevocation", "actual", common.TypeOf(pld.Info))
	}
	if args.SignedRevInfo, err = path_mgmt.NewSignedRevInfoFromRaw(infoRev.RawSRev); err != nil {
		return common.NewBasicError(
			"Unable to decode SignedRevInfo from SCMP InfoRevocation payload", err)
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
		callbacks.rawSRevF(args)
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
		return nil, nil, common.NewBasicError("Unsupported SVC address",
			scmp.NewError(scmp.C_Routing, scmp.T_R_BadHost, nil, nil), "svc", svc)
	}
	if len(elemMap) == 0 {
		return nil, nil, common.NewBasicError("No instances found for SVC address",
			scmp.NewError(scmp.C_Routing, scmp.T_R_UnreachHost, nil, nil), "svc", svc)
	}
	return names, elemMap, nil
}
