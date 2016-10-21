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
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/util"
)

func (p *Packet) Route() *util.Error {
	for _, f := range p.hooks.Route {
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
	for _, epair := range p.Egress {
		epair.F(p)
	}
	return nil
}

func (p *Packet) RouteResolveSVC() (HookResult, *util.Error) {
	svc, ok := p.dstHost.(*addr.HostSVC)
	if !ok {
		return HookError, util.NewError("Destination host is NOT an SVC address",
			"actual", p.dstHost, "type", fmt.Sprintf("%T", p.dstHost))
	}
	intf := conf.C.Net.IFs[*p.ifCurr]
	f := callbacks.locOutFs[intf.LocAddrIdx]
	if svc.IsMulticast() {
		return p.RouteResolveSVCMulti(*svc, f)
	}
	return p.RouteResolveSVCAny(*svc, f)
}

func (p *Packet) RouteResolveSVCAny(svc addr.HostSVC, f OutputFunc) (HookResult, *util.Error) {
	names, elemMap := getSVCNamesMap(svc)
	// XXX(kormat): just pick one randomly. TCP will remove the need to have
	// consistent selection for a given source.
	if elemMap == nil {
		return HookError, util.NewError("No instances found for SVC address", "svc", svc)
	}
	name := names[rand.Intn(len(names))]
	elem := elemMap[name]
	dst := &net.UDPAddr{IP: elem.Addr.IP, Port: overlay.EndhostPort}
	p.Egress = append(p.Egress, EgressPair{f, dst})
	return HookContinue, nil
}

func (p *Packet) RouteResolveSVCMulti(svc addr.HostSVC, f OutputFunc) (HookResult, *util.Error) {
	_, elemMap := getSVCNamesMap(svc)
	if elemMap == nil {
		return HookError, util.NewError("No instances found for SVC address", "svc", svc)
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
		p.Egress = append(p.Egress, EgressPair{f, dst})
	}
	return HookContinue, nil
}

func (p *Packet) forward() (HookResult, *util.Error) {
	switch p.DirFrom {
	case DirExternal:
		return p.forwardFromExternal()
	case DirLocal:
		return p.forwardFromLocal()
	default:
		return HookError, util.NewError("Unsupported forwarding DirFrom", "dirFrom", p.DirFrom)
	}
}

func (p *Packet) forwardFromExternal() (HookResult, *util.Error) {
	if p.hopF.VerifyOnly {
		return HookError, util.NewError("Non-routing HopF, refusing to forward", "hopF", p.hopF)
	}
	intf := conf.C.Net.IFs[*p.ifCurr]
	if *p.dstIA == *conf.C.IA {
		// Destination is local host
		if p.hopF.ForwardOnly {
			return HookError, util.NewError("Delivery forbidden for Forward-only HopF",
				"hopF", p.hopF)
		}
		dst := &net.UDPAddr{IP: p.dstHost.IP(), Port: overlay.EndhostPort}
		p.Egress = append(p.Egress, EgressPair{callbacks.locOutFs[intf.LocAddrIdx], dst})
		return HookContinue, nil
	}
	if p.hopF.Xover {
		if err := p.incPath(); err != nil {
			return HookError, err
		}
		if err := p.validatePath(DirLocal); err != nil {
			return HookError, err
		}
	}
	// Destination is remote, so forward to egress router
	nextIF, err := p.IFNext()
	if err != nil {
		return HookError, err
	}
	if nextIF == nil || *nextIF == 0 {
		return HookError, util.NewError("Invalid next IF", "ifid", *nextIF)
	}
	nextBR, ok := conf.C.TopoMeta.IFMap[int(*nextIF)]
	if !ok {
		return HookError, util.NewError("Unknown next IF", "ifid", nextIF)
	}
	conf.C.IFStates.RLock()
	info, ok := conf.C.IFStates.M[*nextIF]
	conf.C.IFStates.RUnlock()
	if ok && !info.Active() {
		return HookError, util.NewError(ErrorIntfRevoked, "ifid", *nextIF)
	}
	dst := &net.UDPAddr{IP: nextBR.BasicElem.Addr.IP, Port: nextBR.BasicElem.Port}
	p.Egress = append(p.Egress, EgressPair{callbacks.locOutFs[intf.LocAddrIdx], dst})
	return HookContinue, nil
}

func (p *Packet) forwardFromLocal() (HookResult, *util.Error) {
	if p.infoF != nil || len(p.idxs.hbhExt) > 0 {
		if err := p.incPath(); err != nil {
			return HookError, err
		}
	}
	intf := conf.C.Net.IFs[*p.ifCurr]
	p.Egress = append(p.Egress, EgressPair{callbacks.intfOutFs[*p.ifCurr], intf.RemoteAddr})
	return HookContinue, nil
}
