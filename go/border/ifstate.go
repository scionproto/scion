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

// This file handles generating periodic Interface State Request (IFStateReq)
// packets that are sent to the local Beacon Service (BS), as well as
// processing the Interface State updates. IFStateReqs are mostly needed on
// startup, to make sure the border router is aware of the status of the local
// interfaces. The BS normally updates the border routers everytime an
// interface state changes, so this is only needed as a fail-safe after
// startup.

package main

import (
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/proto"
)

// ifStateFreq is how often the router will request an Interface State update
// from the beacon service.
const ifStateFreq = 30 * time.Second

func (r *Router) IFStateUpdate() {
	defer liblog.PanicLog()
	r.genIFStateReq()
	for range time.Tick(ifStateFreq) {
		r.genIFStateReq()
	}
}

// genIFStateReq generates an Interface State request packet to the local
// beacon service.
func (r *Router) genIFStateReq() {
	dstHost := addr.SvcBS.Multicast()
	// Pick first local address from topology as source.
	srcAddr := conf.C.Net.LocAddr[0].PublicAddr()
	// Create base packet
	rp, err := rpkt.RtrPktFromScnPkt(&spkt.ScnPkt{
		DstIA: conf.C.IA, SrcIA: conf.C.IA,
		DstHost: dstHost, SrcHost: addr.HostFromIP(srcAddr.IP),
		L4: &l4.UDP{SrcPort: uint16(srcAddr.Port), DstPort: 0},
	}, rpkt.DirLocal)
	if err != nil {
		log.Error("Error creating IFState packet", err.Ctx...)
		return
	}
	// Create payload
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
	rp.SetPld(&spkt.CtrlPld{SCION: scion})
	_, err = rp.RouteResolveSVCMulti(dstHost, r.locOutFs[0])
	if err != nil {
		log.Error("Unable to route IFStateReq packet", err.Ctx...)
	}
	rp.Route()
}
