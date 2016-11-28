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
	"net"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/assert"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
)

// Route handles routing of packets. Registered hooks are called, allowing them
// to add to the packet's Egress slice, and then the slice is iterated over and
// each entry's function is called with the entry's address as the argument.
// The use of a slice allows for a packet to be sent multiple times (e.g.
// sending IFID packets to all BS instances in the local AS).
func (rp *RtrPkt) Route() *common.Error {
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
		return common.NewError("No routing information found", "egress", rp.Egress,
			"dirFrom", rp.DirFrom, "dirTo", rp.DirTo, "raw", rp.Raw)
	}
	// Call all egress functions.
	for _, epair := range rp.Egress {
		epair.F(rp, epair.Dst)
	}
	return nil
}

// RouteResolveSVC is a hook to resolve SVC addresses for routing packets to
// the local ISD-AS.
func (rp *RtrPkt) RouteResolveSVC() (HookResult, *common.Error) {
	svc, ok := rp.dstHost.(addr.HostSVC)
	if !ok {
		return HookError, common.NewError("Destination host is NOT an SVC address",
			"actual", rp.dstHost, "type", fmt.Sprintf("%T", rp.dstHost))
	}
	intf := conf.C.Net.IFs[*rp.ifCurr]
	f := callbacks.locOutFs[intf.LocAddrIdx]
	if svc.IsMulticast() {
		return rp.RouteResolveSVCMulti(svc, f)
	}
	return rp.RouteResolveSVCAny(svc, f)
}

// RouteResolveSVCAny handles routing a packet to an anycast SVC address (i.e.
// a single instance of a local infrastructure service).
func (rp *RtrPkt) RouteResolveSVCAny(svc addr.HostSVC, f OutputFunc) (HookResult, *common.Error) {
	names, elemMap, err := getSVCNamesMap(svc)
	if err != nil {
		return HookError, err
	}
	// XXX(kormat): just pick one randomly. TCP will remove the need to have
	// consistent selection for a given source.
	name := names[rand.Intn(len(names))]
	elem := elemMap[name]
	dst := &net.UDPAddr{IP: elem.Addr.IP, Port: overlay.EndhostPort}
	rp.Egress = append(rp.Egress, EgressPair{f, dst})
	return HookContinue, nil
}

// RouteResolveSVCMulti handles routing a packet to a multicast SVC address
// (i.e. one packet per machine hosting instances for a local infrastructure
// service).
func (rp *RtrPkt) RouteResolveSVCMulti(svc addr.HostSVC, f OutputFunc) (HookResult, *common.Error) {
	_, elemMap, err := getSVCNamesMap(svc)
	if err != nil {
		return HookError, err
	}
	// Only send once per IP address.
	seen := make(map[string]bool)
	for _, elem := range elemMap {
		strIP := string(elem.Addr.IP)
		if _, ok := seen[strIP]; ok {
			continue
		}
		seen[strIP] = true
		dst := &net.UDPAddr{IP: elem.Addr.IP, Port: overlay.EndhostPort}
		rp.Egress = append(rp.Egress, EgressPair{f, dst})
	}
	return HookContinue, nil
}

func (rp *RtrPkt) forward() (HookResult, *common.Error) {
	switch rp.DirFrom {
	case DirExternal:
		return rp.forwardFromExternal()
	case DirLocal:
		return rp.forwardFromLocal()
	default:
		return HookError, common.NewError("Unsupported forwarding DirFrom", "dirFrom", rp.DirFrom)
	}
}

// forwardFromExternal forwards packets that have been received from a
// neighbouring ISD-AS.
func (rp *RtrPkt) forwardFromExternal() (HookResult, *common.Error) {
	if assert.On {
		assert.Must(rp.hopF != nil, rp.ErrStr("rp.hopF must not be nil"))
	}
	if rp.hopF.VerifyOnly { // Should have been caught by validatePath
		return HookError, common.NewError(
			"BUG: Non-routing HopF, refusing to forward", "hopF", rp.hopF)
	}
	intf := conf.C.Net.IFs[*rp.ifCurr]
	if *rp.dstIA == *conf.C.IA {
		// Destination is a host in the local ISD-AS.
		if rp.hopF.ForwardOnly { // Should have been caught by validatePath
			return HookError, common.NewError("BUG: Delivery forbidden for Forward-only HopF",
				"hopF", rp.hopF)
		}
		dst := &net.UDPAddr{IP: rp.dstHost.IP(), Port: overlay.EndhostPort}
		rp.Egress = append(rp.Egress, EgressPair{callbacks.locOutFs[intf.LocAddrIdx], dst})
		return HookContinue, nil
	}
	// If this is a cross-over Hop Field, increment the path.
	if rp.hopF.Xover {
		if err := rp.IncPath(); err != nil {
			return HookError, err
		}
		// FIXME(kormat): this might need to change when multiple interfaces
		// per router are supported.
		if err := rp.validatePath(DirLocal); err != nil {
			return HookError, err
		}
	}
	// Destination is in a remote ISD-AS, so forward to egress router.
	// FIXME(kormat): this will need to change when multiple interfaces per
	// router are supported.
	nextIF, err := rp.IFNext()
	if err != nil {
		return HookError, err
	}
	if err := rp.validateLocalIF(*nextIF); err != nil {
		return HookError, err
	}
	nextBR := conf.C.TopoMeta.IFMap[int(*nextIF)]
	dst := &net.UDPAddr{IP: nextBR.BasicElem.Addr.IP, Port: nextBR.BasicElem.Port}
	rp.Egress = append(rp.Egress, EgressPair{callbacks.locOutFs[intf.LocAddrIdx], dst})
	return HookContinue, nil
}

// forwardFromLocal handles packet received from the local ISD-AS, to be
// forwarded to neighbouring ISD-ASes.
func (rp *RtrPkt) forwardFromLocal() (HookResult, *common.Error) {
	if rp.infoF != nil || len(rp.idxs.hbhExt) > 0 {
		if err := rp.IncPath(); err != nil {
			return HookError, err
		}
	}
	intf := conf.C.Net.IFs[*rp.ifCurr]
	rp.Egress = append(rp.Egress, EgressPair{callbacks.intfOutFs[*rp.ifCurr], intf.RemoteAddr})
	return HookContinue, nil
}
