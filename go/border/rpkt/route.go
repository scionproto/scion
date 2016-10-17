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
	"math/rand"
	"net"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
)

func (rp *RtrPkt) Route() *common.Error {
	for _, f := range rp.hooks.Route {
		ret, err := f()
		switch {
		case err != nil:
			return err
		case ret == HookContinue:
			continue
		case ret == HookFinish:
			return nil
		}
	}
	if len(rp.Egress) == 0 {
		return common.NewError("No routing information found", "egress", rp.Egress,
			"dirFrom", rp.DirFrom, "dirTo", rp.DirTo, "raw", rp.Raw)
	}
	for _, epair := range rp.Egress {
		epair.F(rp)
	}
	return nil
}

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

func (rp *RtrPkt) RouteResolveSVCAny(svc addr.HostSVC, f OutputFunc) (HookResult, *common.Error) {
	names, elemMap := getSVCNamesMap(svc)
	// XXX(kormat): just pick one randomly. TCP will remove the need to have
	// consistent selection for a given source.
	if elemMap == nil {
		return HookError, common.NewError("No instances found for SVC address", "svc", svc)
	}
	name := names[rand.Intn(len(names))]
	elem := elemMap[name]
	dst := &net.UDPAddr{IP: elem.Addr.IP, Port: overlay.EndhostPort}
	rp.Egress = append(rp.Egress, EgressPair{f, dst})
	return HookContinue, nil
}

func (rp *RtrPkt) RouteResolveSVCMulti(svc addr.HostSVC, f OutputFunc) (HookResult, *common.Error) {
	_, elemMap := getSVCNamesMap(svc)
	if elemMap == nil {
		return HookError, common.NewError("No instances found for SVC address", "svc", svc)
	}
	// Only send once per IP
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

func (rp *RtrPkt) forwardFromExternal() (HookResult, *common.Error) {
	if rp.hopF.VerifyOnly {
		return HookError, common.NewError("Non-routing HopF, refusing to forward", "hopF", rp.hopF)
	}
	intf := conf.C.Net.IFs[*rp.ifCurr]
	if *rp.dstIA == *conf.C.IA {
		// Destination is local host
		if rp.hopF.ForwardOnly {
			return HookError, common.NewError("Delivery forbidden for Forward-only HopF",
				"hopF", rp.hopF)
		}
		dst := &net.UDPAddr{IP: rp.dstHost.IP(), Port: overlay.EndhostPort}
		rp.Egress = append(rp.Egress, EgressPair{callbacks.locOutFs[intf.LocAddrIdx], dst})
		return HookContinue, nil
	}
	if rp.hopF.Xover {
		if err := rp.incPath(); err != nil {
			return HookError, err
		}
		if err := rp.validatePath(DirLocal); err != nil {
			return HookError, err
		}
	}
	// Destination is remote, so forward to egress router
	nextIF, err := rp.IFNext()
	if err != nil {
		return HookError, err
	}
	if nextIF == nil || *nextIF == 0 {
		return HookError, common.NewError("Invalid next IF", "ifid", *nextIF)
	}
	nextBR, ok := conf.C.TopoMeta.IFMap[int(*nextIF)]
	if !ok {
		return HookError, common.NewError("Unknown next IF", "ifid", nextIF)
	}
	conf.C.IFStates.RLock()
	info, ok := conf.C.IFStates.M[*nextIF]
	conf.C.IFStates.RUnlock()
	if ok && !info.P.Active() {
		return HookError, common.NewError(ErrorIntfRevoked, "ifid", *nextIF)
	}
	dst := &net.UDPAddr{IP: nextBR.BasicElem.Addr.IP, Port: nextBR.BasicElem.Port}
	rp.Egress = append(rp.Egress, EgressPair{callbacks.locOutFs[intf.LocAddrIdx], dst})
	return HookContinue, nil
}

func (rp *RtrPkt) forwardFromLocal() (HookResult, *common.Error) {
	if rp.infoF != nil || len(rp.idxs.hbhExt) > 0 {
		if err := rp.incPath(); err != nil {
			return HookError, err
		}
	}
	intf := conf.C.Net.IFs[*rp.ifCurr]
	rp.Egress = append(rp.Egress, EgressPair{callbacks.intfOutFs[*rp.ifCurr], intf.RemoteAddr})
	return HookContinue, nil
}
