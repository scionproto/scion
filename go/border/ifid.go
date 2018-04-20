// Copyright 2018 ETH Zurich
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

// This file handles IFID packets from the local BS.

package main

import (
	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/log"
)

// IFIDCallback is called to enqueue IFIDs for handling by the
// IFIDFwd goroutine.
func (r *Router) IFIDCallback(args rpkt.IFIDCallbackArgs) {
	args.RtrPkt.RefInc(1)
	select {
	case r.ifIDQ <- args:
	default:
		log.Debug("Dropping ifid packet")
		args.RtrPkt.Release()
	}
}

// IFIDFwd handles IFID (interface ID) packets from the local BS
// and forwards them to the remote ISD-AS BR
func (r *Router) IFIDFwd() {
	defer liblog.LogPanicAndExit()
	// Run forever.
	for args := range r.ifIDQ {
		r.fwdLocalIFID(args.RtrPkt)
		args.RtrPkt.Release()
	}
}

// fwdLocalIFID creates RtrPkts and sends them to the remote BR
func (r *Router) fwdLocalIFID(rp *rpkt.RtrPkt) {
	ifCurr, err := rp.IFCurr()
	if err != nil {
		log.Error("Error getting current IF from RtrPkt", "err", err)
		return
	}
	// Create ScnPkt from RtrPkt
	spkt, err := rp.ToScnPkt(true)
	if err != nil {
		log.Error("Error generating ScnPkt from RtrPkt", "err", err)
		return
	}
	ctx := rctx.Get()
	intf := ctx.Conf.Net.IFs[*ifCurr]
	// Set remote BR as Dst
	spkt.DstIA = intf.RemoteIA
	spkt.DstHost = addr.HostFromIP(intf.RemoteAddr.IP)
	if spkt.Path != nil && len(spkt.Path.Raw) > 0 {
		log.Error("Error forwarding IFID packet: Path is present on ScnPkt.")
		return
	}
	srcPort := intf.IFAddr.PublicAddrInfo(intf.IFAddr.Overlay).L4Port
	spkt.L4 = &l4.UDP{SrcPort: uint16(srcPort), DstPort: uint16(intf.RemoteAddr.L4Port)}
	// Convert back to RtrPkt
	fwdrp, err := rpkt.RtrPktFromScnPkt(spkt, rcmn.DirExternal, ctx)
	if err != nil {
		log.Error("Error generating RtrPkt from ScnPkt", "err", err)
		return
	}
	// Forward to remote BR directly
	fwdrp.Egress = append(fwdrp.Egress, rpkt.EgressPair{S: ctx.ExtSockOut[*ifCurr]})
	fwdrp.Route()
}
