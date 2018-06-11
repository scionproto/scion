// Copyright 2017 ETH Zurich
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

// This file provides a generic interface to periodically generate SCION packets
// and send them out.

package main

import (
	"time"

	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	// ifStateFreq is how often the router will request an Interface State update
	// from the beacon service.
	ifStateFreq = 30 * time.Second
)

// genPkt is a generic function to generate packets that originate at the router.
func (r *Router) genPkt(dstIA addr.IA, dstHost addr.HostAddr, dstL4Port int,
	srcAddr *topology.AddrInfo, pld common.Payload) error {
	ctx := rctx.Get()
	dirTo := rcmn.DirExternal
	if dstIA.Eq(ctx.Conf.IA) {
		dirTo = rcmn.DirLocal
	}
	// Create base packet
	sp := &spkt.ScnPkt{
		DstIA: dstIA, SrcIA: ctx.Conf.IA, DstHost: dstHost, SrcHost: addr.HostFromIP(srcAddr.IP),
	}
	// TODO(klausman, kormat): What if it isn't UDP? Handle other overlay types
	if srcAddr.Overlay.IsUDP() {
		sp.L4 = &l4.UDP{SrcPort: uint16(srcAddr.L4Port), DstPort: uint16(dstL4Port)}
	}
	rp, err := rpkt.RtrPktFromScnPkt(sp, dirTo, ctx)
	if err != nil {
		return err
	}
	if err = rp.SetPld(pld); err != nil {
		return err
	}
	if dstIA.Eq(ctx.Conf.IA) {
		if dstHost.Type() == addr.HostTypeSVC {
			if _, err := rp.RouteResolveSVC(); err != nil {
				return err
			}
		} else {
			ai := &topology.AddrInfo{Overlay: srcAddr.Overlay, IP: dstHost.IP(), L4Port: dstL4Port}
			if srcAddr.Overlay.IsUDP() {
				ai.OverlayPort = overlay.EndhostPort
			}
			rp.Egress = append(rp.Egress, rpkt.EgressPair{S: ctx.LocSockOut, Dst: ai})
		}
	} else {
		ifid, ok := ctx.Conf.Net.IFAddrMap[srcAddr.Key()]
		if !ok {
			return common.NewBasicError("genPkt: unable to find ifid for address",
				nil, "addr", srcAddr)
		}
		rp.Egress = append(rp.Egress, rpkt.EgressPair{S: ctx.ExtSockOut[ifid]})
	}
	return rp.Route()
}

// IFStateUpdate handles generating periodic Interface State Request (IFStateReq)
// packets that are sent to the local Beacon Service (BS), as well as
// processing the Interface State updates. IFStateReqs are mostly needed on
// startup, to make sure the border router is aware of the status of the local
// interfaces. The BS normally updates the border routers everytime an
// interface state changes, so this is only needed as a fail-safe after
// startup.
func (r *Router) IFStateUpdate() {
	defer log.LogPanicAndExit()
	r.genIFStateReq()
	for range time.Tick(ifStateFreq) {
		r.genIFStateReq()
	}
}

// genIFStateReq generates an Interface State request packet to the local
// beacon service.
func (r *Router) genIFStateReq() {
	ctx := rctx.Get()
	// Pick first local address from topology as source.
	srcAddr := ctx.Conf.Net.LocAddr.PublicAddrInfo(ctx.Conf.Net.LocAddr.Overlay)
	cpld, err := ctrl.NewPathMgmtPld(&path_mgmt.IFStateReq{}, nil, nil)
	if err != nil {
		log.Error("Error generating IFStateReq Ctrl payload", "err", err)
		return
	}
	scpld, err := cpld.SignedPld(ctrl.NullSigner)
	if err != nil {
		log.Error("Error generating IFStateReq signed Ctrl payload", "err", err)
		return
	}
	if err := r.genPkt(ctx.Conf.IA, addr.SvcBS.Multicast(), 0, srcAddr, scpld); err != nil {
		log.Error("Error generating IFStateReq packet", "err", err)
	}
}
