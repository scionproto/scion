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
	"fmt"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/proto"
)

// ifStateFreq is how often the router will request an Interface State update
// from the beacon service.
const ifStateFreq = 30 * time.Second

func (r *Router) IFStateUpdate() {
	defer liblog.PanicLog()
	r.GenIFStateReq()
	for range time.Tick(ifStateFreq) {
		r.GenIFStateReq()
	}
}

// GenIFStateReq generates an Interface State request packet to the local
// beacon service.
func (r *Router) GenIFStateReq() {
	// Pick first local address from topology as source.
	srcAddr := conf.C.Net.LocAddr[0].PublicAddr()
	dstHost := addr.SvcBS.Multicast()
	// Create base packet
	rp, err := rpkt.RtrPktFromScnPkt(&spkt.ScnPkt{
		SrcIA: conf.C.IA, SrcHost: addr.HostFromIP(srcAddr.IP),
		DstIA: conf.C.IA, DstHost: dstHost,
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

// ProcessIFStates processes Interface State updates from the beacon service.
func (r *Router) ProcessIFStates(ifStates proto.IFStateInfos) {
	infos, serr := ifStates.Infos()
	if serr != nil {
		log.Error("Unable to extract IFStateInfos from message", "err", serr)
		return
	}
	// Convert IFState infos to map
	m := make(map[spath.IntfID]conf.IFState, infos.Len())
	for i := 0; i < infos.Len(); i++ {
		info := infos.At(i)
		ifid := spath.IntfID(info.IfID())
		revInfo, serr := info.RevInfo()
		if serr != nil {
			log.Error("Unable to extract RevInfo from IFStateInfo", "err", serr, "info", info)
			return
		}
		rawRev, err := proto.StructPack(revInfo.Struct)
		if err != nil {
			log.Error("Unable to pack RevInfo", err.Ctx...)
			return
		}
		m[ifid] = conf.IFState{P: info, RawRev: rawRev}
		gauge := metrics.IFState.WithLabelValues(fmt.Sprintf("intf:%d", ifid))
		if info.Active() {
			gauge.Set(1)
		} else {
			gauge.Set(0)
		}
	}
	// Lock local IFState config for writing, and replace existing map
	conf.C.IFStates.Lock()
	conf.C.IFStates.M = m
	conf.C.IFStates.Unlock()
}
