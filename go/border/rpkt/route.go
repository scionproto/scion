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

// This file handles routing of packets.

package rpkt

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/border/metrics"
	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/proto"
)

// Route handles routing of packets. Registered hooks are called, allowing them
// to add to the packet's Egress slice, and then the slice is iterated over and
// each entry's function is called with the entry's address as the argument.
// The use of a slice allows for a packet to be sent multiple times (e.g.
// sending IFID packets to all BS instances in the local AS).
func (rp *RtrPkt) Route() error {
	// First allow any registered hooks to either route the packet themselves,
	// or add entries to the Egress slice.
	for _, f := range rp.hooks.Route {
		ret, err := f()
		switch {
		case err != nil:
			return err
		case ret == HookContinue:
			continue
		case ret == HookFinish:
			// HookFinish in this context means "the packet has already been routed".
			return nil
		}
	}
	if len(rp.Egress) == 0 {
		return common.NewBasicError("No routing information found", nil,
			"egress", rp.Egress, "dirFrom", rp.DirFrom, "raw", rp.Raw)
	}
	rp.RefInc(len(rp.Egress))
	// Call all egress functions.
	for _, epair := range rp.Egress {
		epair.S.Ring.Write(ringbuf.EntryList{&EgressRtrPkt{rp, epair.Dst}}, true)
		inSock := rp.Ingress.Sock
		if inSock == "" {
			inSock = "self"
		}
		metrics.ProcessSockSrcDst.With(
			prometheus.Labels{"inSock": inSock, "outSock": epair.S.Labels["sock"]}).Inc()
	}
	return nil
}

// RouteResolveSVC is a hook to resolve SVC addresses for routing packets to the local ISD-AS.
func (rp *RtrPkt) RouteResolveSVC() (HookResult, error) {
	svc, ok := rp.dstHost.(addr.HostSVC)
	if !ok {
		return HookError, common.NewBasicError("Destination host is NOT an SVC address", nil,
			"actual", rp.dstHost, "type", fmt.Sprintf("%T", rp.dstHost))
	}
	addrs, err := rp.Ctx.ResolveSVC(svc)
	if err != nil {
		return HookError, err
	}
	for _, dst := range addrs {
		// FIXME(sgmonroy) Choose LocSock based on overlay type for dual-stack support
		rp.Egress = append(rp.Egress, EgressPair{S: rp.Ctx.LocSockOut, Dst: dst})
	}
	return HookContinue, nil
}

func (rp *RtrPkt) forward() (HookResult, error) {
	switch rp.DirFrom {
	case rcmn.DirExternal:
		return rp.forwardFromExternal()
	case rcmn.DirLocal:
		return rp.forwardFromLocal()
	default:
		return HookError, common.NewBasicError("Unsupported forwarding DirFrom", nil,
			"dirFrom", rp.DirFrom)
	}
}

func (rp *RtrPkt) drop() (HookResult, error) {
	return HookFinish, nil
}

// forwardFromExternal forwards packets that have been received from a neighbouring ISD-AS.
func (rp *RtrPkt) forwardFromExternal() (HookResult, error) {
	if assert.On {
		assert.Mustf(rp.hopF != nil, rp.ErrStr, "rp.hopF must not be nil")
		assert.Mustf(!rp.hopF.VerifyOnly, rp.ErrStr, "Non-routing HopF")
	}
	// FIXME(kormat): this needs to be cleaner, as it won't work with
	// extensions that replace the path header.
	var onLastSeg = rp.CmnHdr.InfoFOffBytes()+int(rp.infoF.Hops+1)*common.LineLen ==
		rp.CmnHdr.HdrLenBytes()
	if onLastSeg && rp.dstIA.Eq(rp.Ctx.Conf.IA) {
		// Destination is a host in the local ISD-AS.
		l4 := addr.NewL4UDPInfo(overlay.EndhostPort)
		dst, err := overlay.NewOverlayAddr(rp.dstHost, l4)
		if err != nil {
			return HookError, err
		}
		rp.Egress = append(rp.Egress, EgressPair{S: rp.Ctx.LocSockOut, Dst: dst})
		return HookContinue, nil
	}
	// If this is a cross-over Hop Field, increment the path.
	if rp.hopF.Xover {
		if err := rp.xoverFromExternal(); err != nil {
			return HookError, err
		}
	} else if err := rp.validateLocalIF(rp.ifNext); err != nil {
		return HookError, err
	}
	// Destination is in a remote ISD-AS.
	if _, ok := rp.Ctx.Conf.Net.IFs[*rp.ifNext]; ok {
		// Egress interface is local so re-inject the packet
		// and make it look like it arrived in the internal interface
		rp.RefInc(1)
		return rp.reprocess()
	}
	nextBR := rp.Ctx.Conf.Topo.IFInfoMap[*rp.ifNext]
	dst := nextBR.InternalAddrs.PublicOverlay(rp.Ctx.Conf.Topo.Overlay)
	rp.Egress = append(rp.Egress, EgressPair{S: rp.Ctx.LocSockOut, Dst: dst})
	return HookContinue, nil
}

// xoverFromExternal handles XOVER hop fields at the ingress router, including
// a lot of sanity/security checking.
func (rp *RtrPkt) xoverFromExternal() error {
	infoF := rp.infoF
	origIFCurr := *rp.ifCurr
	origIFNext := *rp.ifNext
	var segChgd bool
	var err error
	if segChgd, err = rp.IncPath(); err != nil {
		return err
	}
	if err = rp.validatePath(rcmn.DirLocal); err != nil {
		return err
	}
	if err = rp.validateLocalIF(rp.ifNext); err != nil {
		return err
	}
	// If this is a peering XOVER point.
	if infoF.Peer {
		if segChgd {
			return common.NewBasicError("Path inc on ingress caused illegal peer segment change",
				scmp.NewError(scmp.C_Path, scmp.T_P_BadSegment,
					rp.mkInfoPathOffsets(rp.CmnHdr.CurrInfoF, rp.CmnHdr.CurrHopF), nil))
		}
		origIF := origIFNext
		newIF := *rp.ifNext
		if !infoF.ConsDir {
			rp.ifCurr = nil
			if _, err = rp.IFCurr(); err != nil {
				return err
			}
			// IFCurr should never return nil given that for xover there has to be a path
			origIF = origIFCurr
			newIF = *rp.ifCurr
		}
		if origIF != newIF {
			return common.NewBasicError(
				"Downstream interfaces don't match on peer XOVER hop fields",
				scmp.NewError(scmp.C_Path, scmp.T_P_BadHopField,
					rp.mkInfoPathOffsets(rp.CmnHdr.CurrInfoF, rp.CmnHdr.CurrHopF), nil),
				"orig", origIF, "new", newIF,
			)
		}
		return nil
	}
	if !segChgd {
		// If the segment didn't change, no more checks to make.
		return nil
	}
	prevLink := rp.Ctx.Conf.Net.IFs[origIFCurr].Type
	nextLink := rp.Ctx.Conf.Topo.IFInfoMap[*rp.ifNext].LinkType
	// Never allowed to switch between core segments.
	if prevLink == proto.LinkType_core && nextLink == proto.LinkType_core {
		return common.NewBasicError("Segment change between CORE links",
			scmp.NewError(scmp.C_Path, scmp.T_P_BadSegment,
				rp.mkInfoPathOffsets(rp.CmnHdr.CurrInfoF, rp.CmnHdr.CurrHopF), nil))
	}
	// Only allowed to switch from up- to up-segment if the next link is CORE.
	if !infoF.ConsDir && !rp.infoF.ConsDir && nextLink != proto.LinkType_core {
		return common.NewBasicError(
			"Segment change from up segment to up segment with non-CORE next link",
			scmp.NewError(scmp.C_Path, scmp.T_P_BadSegment,
				rp.mkInfoPathOffsets(rp.CmnHdr.CurrInfoF, rp.CmnHdr.CurrHopF), nil),
			"prevLink", prevLink, "nextLink", nextLink,
		)
	}
	// Only allowed to switch from down- to down-segment if the previous link is CORE.
	if infoF.ConsDir && rp.infoF.ConsDir && prevLink != proto.LinkType_core {
		return common.NewBasicError(
			"Segment change from down segment to down segment with non-CORE previous link",
			scmp.NewError(scmp.C_Path, scmp.T_P_BadSegment,
				rp.mkInfoPathOffsets(rp.CmnHdr.CurrInfoF, rp.CmnHdr.CurrHopF), nil),
			"prevLink", prevLink, "nextLink", nextLink,
		)
	}
	// Make sure we drop packets with shortcuts in core links.
	if rp.infoF.Shortcut && nextLink == proto.LinkType_core {
		return common.NewBasicError("Shortcut not allowed on core segment", nil)
	}
	return nil
}

// forwardFromLocal handles packet received from the local ISD-AS, to be
// forwarded to neighbouring ISD-ASes.
func (rp *RtrPkt) forwardFromLocal() (HookResult, error) {
	if rp.infoF != nil || len(rp.idxs.hbhExt) > 0 {
		if _, err := rp.IncPath(); err != nil {
			return HookError, err
		}
	}
	rp.Egress = append(rp.Egress, EgressPair{S: rp.Ctx.ExtSockOut[*rp.ifCurr]})
	return HookContinue, nil
}

func (rp *RtrPkt) reprocess() (HookResult, error) {
	// save
	ctx := rp.Ctx
	free := rp.Free
	// XXX We might need to reconsider keeping timeIn value due to effect on metrics.
	timeIn := rp.TimeIn
	raw := rp.Raw
	refCnt := rp.refCnt
	// reset
	rp.Reset()
	// restore
	rp.Ctx = ctx
	rp.Free = free
	rp.TimeIn = timeIn
	rp.Raw = raw
	rp.refCnt = refCnt
	// set as incoming from local interface
	rp.DirFrom = rcmn.DirLocal
	s := rp.Ctx.LocSockIn
	rp.Ingress.Dst = s.Conn.LocalAddr()
	rp.Ingress.Src = s.Conn.LocalAddr()
	rp.Ingress.IfID = s.Ifid
	rp.Ingress.Sock = s.Labels["sock"]
	// XXX This hook is meant to be called only when processing packets from external to external
	// interface. Thus, the goroutine writing to the LocIn ringbuffer should always be the ones
	// NOT reading from it to avoid deadlock, ie. goroutines handling packets from external
	// interfaces.
	s.Ring.Write(ringbuf.EntryList{rp}, true)
	// Stop routing the packet after enqueuing it back into the ringbuffer.
	return HookFinish, nil
}
