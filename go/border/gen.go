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

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/rcmn"
	"github.com/netsec-ethz/scion/go/border/rctx"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl"
	"github.com/netsec-ethz/scion/go/lib/ctrl/ifid"
	"github.com/netsec-ethz/scion/go/lib/ctrl/path_mgmt"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/topology"
)

const (
	// ifIDFreq is how often IFID packets are sent to the neighbouring AS.
	ifIDFreq = 1 * time.Second
	// ifStateFreq is how often the router will request an Interface State update
	// from the beacon service.
	ifStateFreq = 30 * time.Second
)

// genPkt is a generic function to generate packets that originate at the router.
func (r *Router) genPkt(dstIA *addr.ISD_AS, dstHost addr.HostAddr, dstL4Port int,
	srcAddr *topology.AddrInfo, pld common.Payload) *common.Error {
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
			rp.Egress = append(rp.Egress, rpkt.EgressPair{S: ctx.LocSockOut[0], Dst: ai})
		}
	} else {
		ifid := ctx.Conf.Net.IFAddrMap[srcAddr.Key()]
		rp.Egress = append(rp.Egress, rpkt.EgressPair{S: ctx.ExtSockOut[ifid]})
	}
	return rp.Route()
}

// SyncInterface handles generating periodic Interface ID (IFID) packets that are
// sent to the Beacon Service in the neighbouring AS. These function as both
// keep-alives, and to inform the neighbour of the local interface ID.
func (r *Router) SyncInterface() {
	defer liblog.LogPanicAndExit()
	for range time.Tick(ifIDFreq) {
		ctx := rctx.Get()
		for ifid := range ctx.Conf.Net.IFs {
			r.genIFIDPkt(ifid, ctx)
		}
	}
}

// genIFIDPkt generates an IFID-packet for the specified interface.
func (r *Router) genIFIDPkt(ifID common.IFIDType, ctx *rctx.Ctx) {
	logger := log.New("ifid", ifID)
	intf := ctx.Conf.Net.IFs[ifID]
	srcAddr := intf.IFAddr.PublicAddrInfo(intf.IFAddr.Overlay)
	cpld, cerr := ctrl.NewPld(&ifid.IFID{OrigIfID: uint64(ifID)})
	if cerr != nil {
		logger.Error("Error generating IFID payload", cerr.Ctx...)
		return
	}
	if err := r.genPkt(intf.RemoteIA, addr.HostFromIP(intf.RemoteAddr.IP),
		intf.RemoteAddr.L4Port, srcAddr, cpld); err != nil {
		logger.Error("Error generating IFID packet", err.Ctx...)
	}
}

// IFStateUpdate handles generating periodic Interface State Request (IFStateReq)
// packets that are sent to the local Beacon Service (BS), as well as
// processing the Interface State updates. IFStateReqs are mostly needed on
// startup, to make sure the border router is aware of the status of the local
// interfaces. The BS normally updates the border routers everytime an
// interface state changes, so this is only needed as a fail-safe after
// startup.
func (r *Router) IFStateUpdate() {
	defer liblog.LogPanicAndExit()
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
	srcAddr := ctx.Conf.Net.LocAddr[0].PublicAddrInfo(ctx.Conf.Net.LocAddr[0].Overlay)
	cpld, cerr := ctrl.NewPathMgmtPld(&path_mgmt.IFStateReq{})
	if cerr != nil {
		log.Error("Error generating IFStateReq payload", cerr.Ctx...)
		return
	}
	if err := r.genPkt(ctx.Conf.IA, addr.SvcBS.Multicast(), 0, srcAddr, cpld); err != nil {
		log.Error("Error generating IFStateReq packet", err.Ctx...)
	}
}
