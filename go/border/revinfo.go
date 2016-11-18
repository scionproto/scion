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
	"bytes"

	log "github.com/inconshreveable/log15"
	"zombiezen.com/go/capnproto2"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/proto"
)

func (r *Router) RevTokenCallback(b common.RawBytes) {
	select {
	case r.revInfoQ <- b:
	default:
		log.Debug("Dropping rev token")
	}
}

func (r *Router) RevInfoFwd() {
	defer liblog.PanicLog()
	for b := range r.revInfoQ {
		revInfo := r.decodeRevToken(b)
		if revInfo == nil {
			continue
		}
		r.fwdRevInfo(revInfo, addr.SvcBS.Multicast())
		r.fwdRevInfo(revInfo, addr.SvcPS.Multicast())
	}

}

func (r *Router) decodeRevToken(b common.RawBytes) *proto.RevInfo {
	buf := bytes.NewBuffer(b)
	msg, err := capnp.NewPackedDecoder(buf).Decode()
	if err != nil {
		log.Error("Decoding revocation token failed", "err", err)
		return nil
	}
	// Handle any panics while parsing
	defer func() {
		if err := recover(); err != nil {
			log.Error("Parsing revocation token failed", "err", err)
		}
	}()
	revInfo, err := proto.ReadRootRevInfo(msg)
	if err != nil {
		log.Error("Reading RevInfo from revocation token failed", "err", err)
		return nil
	}
	return &revInfo
}

func (r *Router) fwdRevInfo(revInfo *proto.RevInfo, dstHost addr.HostAddr) {
	// Pick first local address as source
	srcAddr := conf.C.Net.LocAddr[0].PublicAddr()
	// Create base packet
	rp, err := rpkt.RtrPktFromScnPkt(&spkt.ScnPkt{
		SrcIA: conf.C.IA, SrcHost: addr.HostFromIP(srcAddr.IP),
		DstIA: conf.C.IA, DstHost: dstHost,
		L4: &l4.UDP{SrcPort: uint16(srcAddr.Port), DstPort: 0},
	}, rpkt.DirLocal)
	if err != nil {
		log.Error("Error creating RevInfo packet", err.Ctx...)
		return
	}
	scion, pathMgmt, err := proto.NewPathMgmtMsg()
	if err != nil {
		log.Error("Error creating PathMgmt payload", err.Ctx...)
		return
	}
	pathMgmt.SetRevInfo(*revInfo)
	rp.SetPld(&spkt.CtrlPld{SCION: scion})
	_, err = rp.RouteResolveSVCMulti(*dstHost.(*addr.HostSVC), r.locOutFs[0])
	if err != nil {
		log.Error("Unable to route RevInfo packet", err.Ctx...)
		return
	}
	rp.Route()
	log.Debug("Forwarded RevInfo")
}
