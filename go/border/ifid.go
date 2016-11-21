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

// This file handles generating periodic Interface ID (IFID) packets that are
// sent to the Beacon Service in the neighbouring AS. These function as both
// keep-alives, and to inform the neighbour of the local interface ID.

package main

import (
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/proto"
)

// ifIDFreq is how often IFID packets are sent to the neighbouring AS.
const ifIDFreq = 1 * time.Second

func (r *Router) SyncInterface() {
	defer liblog.PanicLog()
	for range time.Tick(ifIDFreq) {
		r.GenIFIDPkts()
	}
}

func (r *Router) GenIFIDPkts() {
	for ifid := range conf.C.Net.IFs {
		r.GenIFIDPkt(ifid)
	}
}

// GenIFIDPkt generates IFID packets.
func (r *Router) GenIFIDPkt(ifid spath.IntfID) {
	logger := log.New("ifid", ifid)
	intf := conf.C.Net.IFs[ifid]
	srcAddr := intf.IFAddr.PublicAddr()
	// Create base packet
	rp, err := rpkt.RtrPktFromScnPkt(&spkt.ScnPkt{
		SrcIA: conf.C.IA, SrcHost: addr.HostFromIP(srcAddr.IP),
		DstIA: intf.RemoteIA, DstHost: addr.HostFromIP(intf.RemoteAddr.IP),
		L4: &l4.UDP{SrcPort: uint16(srcAddr.Port), DstPort: uint16(intf.RemoteAddr.Port)},
	}, rpkt.DirExternal)
	if err != nil {
		logger.Error("Error creating IFID packet", err.Ctx...)
		return
	}
	rp.Egress = append(rp.Egress, rpkt.EgressPair{F: r.intfOutFs[ifid], Dst: intf.RemoteAddr})
	// Create IFID msg
	scion, ifidMsg, err := proto.NewIFIDMsg()
	if err != nil {
		logger.Error("Error creating IFID payload", err.Ctx...)
		return
	}
	ifidMsg.SetOrigIF(uint16(ifid))
	rp.SetPld(&spkt.CtrlPld{SCION: scion})
	rp.Route()
}
