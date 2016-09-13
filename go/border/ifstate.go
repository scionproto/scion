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

package main

import (
	"fmt"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/packet"
	"github.com/netsec-ethz/scion/go/border/path"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/topology"
	"github.com/netsec-ethz/scion/go/proto"
)

const IFStateFreq = 30 * time.Second

func (r *Router) IFStateUpdate() {
	defer liblog.PanicLog()
	r.GenIFStateReq()
	for range time.Tick(IFStateFreq) {
		r.GenIFStateReq()
	}
}

func (r *Router) GenIFStateReq() {
	// Pick first local address as source
	srcAddr := conf.C.Net.LocAddr[0].PublicAddr()
	dstHost := addr.SvcBS.Multicast()
	// Create base packet
	pkt, err := packet.CreateCtrlPacket(packet.DirLocal,
		addr.HostFromIP(srcAddr.IP), topology.Curr.T.IA, dstHost)
	if err != nil {
		log.Error("Error creating IFStateReq packet", err.Ctx...)
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
	pkt.AddL4UDP(srcAddr.Port, 0)
	pkt.AddCtrlPld(scion)
	_, err = pkt.RouteResolveSVCMulti(*dstHost, r.locOutFs[0])
	if err != nil {
		log.Error("Unable to route IFStateReq packet", err.Ctx...)
	}
	pkt.Route()
}

func (r *Router) ProcessIFStates(ifStates proto.IFStateInfos) {
	infos, err := ifStates.Infos()
	if err != nil {
		log.Error("Unable to extract IFStateInfos from message", "err", err)
		return
	}
	// Convert to map
	m := make(map[path.IntfID]proto.IFStateInfo)
	for i := 0; i < infos.Len(); i++ {
		info := infos.At(i)
		ifid := path.IntfID(info.IfID())
		m[ifid] = info
		gauge := metrics.IFState.WithLabelValues(fmt.Sprintf("intf:%d", ifid))
		if info.Active() {
			gauge.Set(1)
		} else {
			gauge.Set(0)
		}
	}
	// Lock for writing, and replace existing map
	conf.C.IFStates.Lock()
	conf.C.IFStates.M = m
	conf.C.IFStates.Unlock()
}
