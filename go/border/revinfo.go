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

// This file handles Revocation Info (RevInfo) packets.

package main

import (
	"bytes"

	log "github.com/inconshreveable/log15"
	"zombiezen.com/go/capnproto2"

	"github.com/netsec-ethz/scion/go/border/rctx"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/proto"
)

// RevTokenCallback is called to enqueue RevInfos for handling by the
// RevInfoFwd goroutine.
func (r *Router) RevTokenCallback(args rpkt.RevTokenCallbackArgs) {
	select {
	case r.revInfoQ <- args:
	default:
		log.Debug("Dropping rev token")
	}
}

// RevInfoFwd takes RevInfos, and forwards them to the local Beacon Service
// (BS) and Path Service (PS).
func (r *Router) RevInfoFwd() {
	defer liblog.PanicLog()
	// Run forever.
	for args := range r.revInfoQ {
		revInfo := r.decodeRevToken(args.RevInfo)
		if revInfo == nil {
			continue
		}
		log.Debug("Forwarding revocation", "revInfo", revInfo.Pretty(), "targets", args.Addrs)
		for _, svcAddr := range args.Addrs {
			r.fwdRevInfo(revInfo, &svcAddr)
		}
	}

}

// decodeRevToken decodes RevInfo payloads.
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

// fwdRevInfo forwards RevInfo payloads to a designated local host.
func (r *Router) fwdRevInfo(revInfo *proto.RevInfo, dstHost addr.HostAddr) {
	ctx := rctx.Get()
	// Pick first local address from topology as source.
	srcAddr := ctx.Conf.Net.LocAddr[0].PublicAddr()
	scion, pathMgmt, err := proto.NewPathMgmtMsg()
	if err != nil {
		log.Error("Error creating PathMgmt payload", err.Ctx...)
		return
	}
	pathMgmt.SetRevInfo(*revInfo)
	if err := r.genPkt(ctx.Conf.IA, *dstHost.(*addr.HostSVC), 0, srcAddr,
		&spkt.CtrlPld{SCION: scion}); err != nil {
		log.Error("Error generating RevInfo packet", err.Ctx...)
	}
}
