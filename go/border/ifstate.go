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
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/packet"
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
	srcAddr := r.NetConf.LocAddr[0].PublicAddr()
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
	_, err = pkt.RouteResolveSVCMulti(dstHost, r.locOutQs[0])
	if err != nil {
		log.Error("Unable to route IFStateReq packet", err.Ctx...)
	}
	pkt.Route()
}
