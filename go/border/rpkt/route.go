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
	"math/rand"

	//log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/rcmn"
	"github.com/netsec-ethz/scion/go/border/rctx"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/assert"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/topology"
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
			// HookFinish in this context means "the packet has already been
			// routed".
			return nil
		}
	}
	if len(rp.Egress) == 0 {
		return common.NewCError("No routing information found", "egress", rp.Egress,
			"dirFrom", rp.DirFrom, "dirTo", rp.DirTo, "raw", rp.Raw)
	}
	rp.refCnt += len(rp.Egress)
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

// RouteResolveSVC is a hook to resolve SVC addresses for routing packets to
// the local ISD-AS.
func (rp *RtrPkt) RouteResolveSVC() (HookResult, error) {
	svc, ok := rp.dstHost.(addr.HostSVC)
	if !ok {
		return HookError, common.NewCError("Destination host is NOT an SVC address",
			"actual", rp.dstHost, "type", fmt.Sprintf("%T", rp.dstHost))
	}
	// Use any local output sock in case the packet has no path (e.g., ifstate requests)
	s := rp.Ctx.LocSockOut[0]
	if rp.ifCurr != nil {
		intf := rp.Ctx.Conf.Net.IFs[*rp.ifCurr]
		s = rp.Ctx.LocSockOut[intf.LocAddrIdx]
	}
	if svc.IsMulticast() {
		return rp.RouteResolveSVCMulti(svc, s)
	}
	return rp.RouteResolveSVCAny(svc, s)
}

// RouteResolveSVCAny handles routing a packet to an anycast SVC address (i.e.
// a single instance of a local infrastructure service).
func (rp *RtrPkt) RouteResolveSVCAny(
	svc addr.HostSVC, s *rctx.Sock) (HookResult, error) {
	names, elemMap, err := getSVCNamesMap(svc, rp.Ctx)
	if err != nil {
		return HookError, err
	}
	// XXX(kormat): just pick one randomly. TCP will remove the need to have
	// consistent selection for a given source.
	name := names[rand.Intn(len(names))]
	elem := elemMap[name]
	dst := elem.PublicAddrInfo(rp.Ctx.Conf.Topo.Overlay)
	rp.Egress = append(rp.Egress, EgressPair{s, dst})
	return HookContinue, nil
}

// RouteResolveSVCMulti handles routing a packet to a multicast SVC address
// (i.e. one packet per machine hosting instances for a local infrastructure
// service).
func (rp *RtrPkt) RouteResolveSVCMulti(
	svc addr.HostSVC, s *rctx.Sock) (HookResult, error) {
	_, elemMap, err := getSVCNamesMap(svc, rp.Ctx)
	if err != nil {
		return HookError, err
	}
	// Only send once per IP:OverlayPort combination. Adding the overlay port
	// allows this to work even when multiple instances are NAT'd to the same
	// IP address.
	seen := make(map[string]struct{})
	for _, elem := range elemMap {
		ai := elem.PublicAddrInfo(rp.Ctx.Conf.Topo.Overlay)
		strIP := fmt.Sprintf("%s:%d", ai.IP, ai.OverlayPort)
		if _, ok := seen[strIP]; ok {
			continue
		}
		seen[strIP] = struct{}{}
		rp.Egress = append(rp.Egress, EgressPair{s, ai})
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
		return HookError, common.NewCError("Unsupported forwarding DirFrom", "dirFrom", rp.DirFrom)
	}
}

// forwardFromExternal forwards packets that have been received from a
// neighbouring ISD-AS.
func (rp *RtrPkt) forwardFromExternal() (HookResult, error) {
	if assert.On {
		assert.Mustf(rp.hopF != nil, rp.ErrStr, "rp.hopF must not be nil")
	}
	if rp.hopF.VerifyOnly { // Should have been caught by validatePath
		return HookError, common.NewCError(
			"BUG: Non-routing HopF, refusing to forward", "hopF", rp.hopF)
	}
	intf := rp.Ctx.Conf.Net.IFs[*rp.ifCurr]
	// FIXME(kormat): this needs to be cleaner, as it won't work with
	// extensions that replace the path header.
	var onLastSeg = rp.CmnHdr.InfoFOffBytes()+int(rp.infoF.Hops+1)*common.LineLen ==
		rp.CmnHdr.HdrLenBytes()
	if onLastSeg && rp.dstIA.Eq(rp.Ctx.Conf.IA) {
		// Destination is a host in the local ISD-AS.
		if rp.hopF.ForwardOnly { // Should have been caught by validatePath
			return HookError, common.NewCError("BUG: Delivery forbidden for Forward-only HopF",
				"hopF", rp.hopF)
		}
		ot := overlay.OverlayFromIP(rp.dstHost.IP(), rp.Ctx.Conf.Topo.Overlay)
		dst := &topology.AddrInfo{
			Overlay:     ot,
			IP:          rp.dstHost.IP(),
			OverlayPort: overlay.EndhostPort,
		}
		rp.Egress = append(rp.Egress, EgressPair{rp.Ctx.LocSockOut[intf.LocAddrIdx], dst})
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
	// Destination is in a remote ISD-AS, so forward to egress router.
	// FIXME(kormat): this will need to change when multiple interfaces per
	// router are supported.
	nextBR := rp.Ctx.Conf.Topo.IFInfoMap[*rp.ifNext]
	nextAI := nextBR.InternalAddr.PublicAddrInfo(rp.Ctx.Conf.Topo.Overlay)
	ot := overlay.OverlayFromIP(nextAI.IP, rp.Ctx.Conf.Topo.Overlay)
	dst := &topology.AddrInfo{
		Overlay:     ot,
		IP:          nextAI.IP,
		L4Port:      nextAI.L4Port,
		OverlayPort: nextAI.L4Port,
	}
	rp.Egress = append(rp.Egress, EgressPair{rp.Ctx.LocSockOut[intf.LocAddrIdx], dst})
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
			sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_BadSegment, rp.mkInfoPathOffsets())
			return common.NewCError(
				"Path inc on ingress caused illegal peer segment change", sdata)
		}
		origIF := origIFNext
		newIF := *rp.ifNext
		if infoF.Up {
			rp.ifCurr = nil
			if _, err = rp.IFCurr(); err != nil {
				return err
			}
			origIF = origIFCurr
			newIF = *rp.ifCurr
		}
		if origIF != newIF {
			sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_BadHopField, rp.mkInfoPathOffsets())
			return common.NewCError(
				"Downstream interfaces don't match on peer XOVER hop fields", sdata,
				"orig", origIF, "new", newIF)
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
	if prevLink == topology.CoreLink && nextLink == topology.CoreLink {
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_BadSegment, rp.mkInfoPathOffsets())
		return common.NewCError("Segment change between CORE links.", sdata)
	}
	// Only allowed to switch from up- to up-segment if the next link is CORE.
	if infoF.Up && rp.infoF.Up && nextLink != topology.CoreLink {
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_BadSegment, rp.mkInfoPathOffsets())
		return common.NewCError(
			"Segment change from up segment to up segment with non-CORE next link", sdata,
			"prevLink", prevLink, "nextLink", nextLink)
	}
	// Only allowed to switch from down- to down-segment if the previous link is CORE.
	if !infoF.Up && !rp.infoF.Up && prevLink != topology.CoreLink {
		sdata := scmp.NewErrData(scmp.C_Path, scmp.T_P_BadSegment, rp.mkInfoPathOffsets())
		return common.NewCError(
			"Segment change from down segment to down segment with non-CORE previous link",
			sdata, "prevLink", prevLink, "nextLink", nextLink)
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
	rp.Egress = append(rp.Egress, EgressPair{rp.Ctx.ExtSockOut[*rp.ifCurr], nil})
	return HookContinue, nil
}
