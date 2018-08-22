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
	"time"

	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/proto"
)

// NeedsLocalProcessing determines if the router needs to do more than just
// forward a packet (e.g. resolve an SVC destination address).
func (rp *RtrPkt) NeedsLocalProcessing() error {
	// Check if SVC packet to local AS
	if rp.dstIA.Eq(rp.Ctx.Conf.IA) && rp.CmnHdr.DstType == addr.HostTypeSVC {
		// SVC address needs to be resolved for delivery.
		rp.hooks.Route = append(rp.hooks.Route, rp.RouteResolveSVC)
	} else {
		// Packet not destined to local AS, just forward.
		// Non-SVC packet to local AS, just forward.
		rp.hooks.Route = append(rp.hooks.Route, rp.forward)
	}
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
	// Forward reply
	reply.Route()
	// Drop original packet prepending drop hook so it is the first one to run.
	rp.hooks.Route = append([]hookRoute{rp.drop}, rp.hooks.Route...)
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
	if (rp.dstIA.I == rp.Ctx.Conf.Topo.ISD_AS.I && intf.Type == proto.LinkType_core) ||
		(rp.srcIA.I == rp.Ctx.Conf.Topo.ISD_AS.I && intf.Type == proto.LinkType_parent) {
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
