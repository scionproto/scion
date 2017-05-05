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
)

type genPldHook func() (*proto.SCION, *common.Error)
type configRpktHook func(rp *rpkt.RtrPkt) *common.Error

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

func (r *Router) genPkt(dstHost addr.HostAddr, dirTo rpkt.Dir, genPld genPldHook,
	configHook configRpktHook) *common.Error {
	// Pick first local address from topology as source.
	srcAddr := conf.C.Net.LocAddr[0].PublicAddr()
	// Create base packet
	rp, err := rpkt.RtrPktFromScnPkt(&spkt.ScnPkt{
		DstIA: conf.C.IA, SrcIA: conf.C.IA,
		DstHost: dstHost, SrcHost: addr.HostFromIP(srcAddr.IP),
		L4: &l4.UDP{SrcPort: uint16(srcAddr.Port), DstPort: 0},
	}, dirTo)
	if err != nil {
		return err
	}
	pld, err := genPld()
	if err != nil {
		return err
	}
	rp.SetPld(&spkt.CtrlPld{SCION: pld})
	if configHook != nil {
		configHook(rp)
	}
	return rp.Route()
}

func (r *Router) genIFIDPkts() {
	for ifid := range conf.C.Net.IFs {
		r.GenIFIDPkt(ifid)
	}
}

func (r *Router) genIFIDPkt(ifid spath.IntfID) {
	logger := log.New("ifid", ifid)
	intf := conf.C.Net.IFs[ifid]
	err := r.genPkt(addr.HostFromIP(intf.RemoteAddr.IP), rpkt.DirExternal,
		func() (*proto.SCION, *common.Error) {
			scion, ifidMsg, err := proto.NewIFIDMsg()
			if err != nil {
				return nil, common.NewError("Error creating IFID payload", err.Ctx...)
			}
			ifidMsg.SetOrigIF(uint16(ifid))
			return scion, nil
		},
		func(rp *rpkt.RtrPkt) *common.Error {
			rp.Egress = append(rp.Egress, rpkt.EgressPair{F: r.intfOutFs[ifid],
				Dst: intf.RemoteAddr})
			return nil
		})
	if err != nil {
		logger.Error("Error generating IFID packet", err.Ctx...)
	}
}

// genIFStateReq generates an Interface State request packet to the local
// beacon service.
func (r *Router) genIFStateReq() {
	dstHost := addr.SvcBS.Multicast()
	err := r.genPkt(dstHost, rpkt.DirLocal,
		func() (*proto.SCION, *common.Error) {
			scion, pathMgmt, err := proto.NewPathMgmtMsg()
			if err != nil {
				return nil, common.NewError("Error creating PathMgmt payload", err.Ctx...)
			}
			_, cerr := pathMgmt.NewIfStateReq()
			if cerr != nil {
				return nil, common.NewError("Unable to create IFStateReq struct", "err", cerr)
			}
			return scion, nil
		},
		func(rp *rpkt.RtrPkt) *common.Error {
			if _, err := rp.RouteResolveSVCMulti(dstHost, r.locOutFs[0]); err != nil {
				return common.NewError("Unable to route IFStateReq packet", err.Ctx...)
			}
			return nil
		})
	if err != nil {
		log.Error("Error generating IFID packet", err.Ctx...)
	}
}

// genRevInfo forwards RevInfo payloads to a designated local host.
func (r *Router) genRevInfo(revInfo *proto.RevInfo, dstHost addr.HostAddr) {
	err := r.genPkt(dstHost, rpkt.DirLocal,
		func() (*proto.SCION, *common.Error) {
			scion, pathMgmt, err := proto.NewPathMgmtMsg()
			if err != nil {
				return nil, common.NewError("Error creating PathMgmt payload", err.Ctx...)
			}
			pathMgmt.SetRevInfo(*revInfo)
			return scion, nil
		},
		func(rp *rpkt.RtrPkt) *common.Error {
			_, err := rp.RouteResolveSVCMulti(*dstHost.(*addr.HostSVC), r.locOutFs[0])
			if err != nil {
				return common.NewError("Unable to route RevInfo packet", err.Ctx...)
			}
			return nil
		})
}
