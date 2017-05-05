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
	"net"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/proto"
)

const (
	// ifIDFreq is how often IFID packets are sent to the neighbouring AS.
	ifIDFreq = 1 * time.Second
	// ifStateFreq is how often the router will request an Interface State update
	// from the beacon service.
	ifStateFreq = 30 * time.Second
)

// SyncInterface handles generating periodic Interface ID (IFID) packets that are
// sent to the Beacon Service in the neighbouring AS. These function as both
// keep-alives, and to inform the neighbour of the local interface ID.
func (r *Router) SyncInterface() {
	defer liblog.PanicLog()
	for range time.Tick(ifIDFreq) {
		r.genIFIDPkts()
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
	defer liblog.PanicLog()
	r.genIFStateReq()
	for range time.Tick(ifStateFreq) {
		r.genIFStateReq()
	}
}

func (r *Router) genPkt(dstIA *addr.ISD_AS, dstHost addr.HostAddr, dstPort int,
	srcAddr *net.UDPAddr, pld *spkt.CtrlPld) *common.Error {
	dirTo := rpkt.DirExternal
	if dstIA.Eq(conf.C.IA) {
		dirTo = rpkt.DirLocal
	}
	// Create base packet
	rp, err := rpkt.RtrPktFromScnPkt(&spkt.ScnPkt{
		DstIA: dstIA, SrcIA: conf.C.IA, DstHost: dstHost, SrcHost: addr.HostFromIP(srcAddr.IP),
		L4: &l4.UDP{SrcPort: uint16(srcAddr.Port), DstPort: uint16(dstPort)},
	}, dirTo)
	if err != nil {
		return err
	}
	if err = rp.SetPld(pld); err != nil {
		return err
	}
	if dstIA.Eq(conf.C.IA) {
		if dstHost.Type() == addr.HostTypeSVC {
			if _, err := rp.RouteResolveSVC(); err != nil {
				return err
			}
		} else {
			rp.Egress = append(rp.Egress, rpkt.EgressPair{
				F: r.locOutFs[0], Dst: &net.UDPAddr{IP: dstHost.IP(), Port: dstPort}})
		}
	} else {
		ifid := conf.C.Net.IFAddrMap[srcAddr.String()]
		intf := conf.C.Net.IFs[ifid]
		rp.Egress = append(rp.Egress, rpkt.EgressPair{F: r.intfOutFs[ifid], Dst: intf.RemoteAddr})
	}
	return rp.Route()
}

func (r *Router) genIFIDPkts() {
	for ifid := range conf.C.Net.IFs {
		r.genIFIDPkt(ifid)
	}
}

// genIFIDPkt generates an IFID-packet for the specified interface.
func (r *Router) genIFIDPkt(ifid spath.IntfID) {
	logger := log.New("ifid", ifid)
	intf := conf.C.Net.IFs[ifid]
	srcAddr := intf.IFAddr.PublicAddr()
	scion, ifidMsg, err := proto.NewIFIDMsg()
	if err != nil {
		logger.Error("Error creating IFID payload", err.Ctx...)
		return
	}
	ifidMsg.SetOrigIF(uint16(ifid))
	if err := r.genPkt(intf.RemoteIA, addr.HostFromIP(intf.RemoteAddr.IP),
		intf.RemoteAddr.Port, srcAddr, &spkt.CtrlPld{SCION: scion}); err != nil {
		logger.Error("Error generating IFID packet", err.Ctx...)
	}
}

// genIFStateReq generates an Interface State request packet to the local
// beacon service.
func (r *Router) genIFStateReq() {
	// Pick first local address from topology as source.
	srcAddr := conf.C.Net.LocAddr[0].PublicAddr()
	scion, pathMgmt, err := proto.NewPathMgmtMsg()
	if err != nil {
		log.Error("Error creating PathMgmt payload", err.Ctx...)
		return
	}
	_, cerr := pathMgmt.NewIfStateReq()
	if cerr != nil {
		log.Error("Unable to create IFStateReq struct", "err", cerr)
		return
	}
	if err := r.genPkt(conf.C.IA, addr.SvcBS.Multicast(), 0, srcAddr,
		&spkt.CtrlPld{SCION: scion}); err != nil {
		log.Error("Error generating IFID packet", err.Ctx...)
	}
}

// genRevInfo forwards RevInfo payloads to a designated local host.
func (r *Router) genRevInfo(revInfo *proto.RevInfo, dstHost addr.HostAddr) {
	// Pick first local address from topology as source.
	srcAddr := conf.C.Net.LocAddr[0].PublicAddr()
	scion, pathMgmt, err := proto.NewPathMgmtMsg()
	if err != nil {
		log.Error("Error creating PathMgmt payload", err.Ctx...)
		return
	}
	pathMgmt.SetRevInfo(*revInfo)
	if err := r.genPkt(conf.C.IA, *dstHost.(*addr.HostSVC), 0, srcAddr,
		&spkt.CtrlPld{SCION: scion}); err != nil {
		log.Error("Error generating RevInfo packet", err.Ctx...)
	}
}
