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
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
)

// RawSRevCallback is called to enqueue RevInfos for handling by the
// RevInfoFwd goroutine.
func (r *Router) RawSRevCallback(args rpkt.RawSRevCallbackArgs) {
	select {
	case r.sRevInfoQ <- args:
	default:
		log.Debug("Dropping rev token")
	}
}

// RevInfoFwd takes RevInfos, and forwards them to the local Beacon Service
// (BS) and Path Service (PS).
func (r *Router) RevInfoFwd() {
	defer log.LogPanicAndExit()
	// Run forever.
	for args := range r.sRevInfoQ {
		revInfo, err := args.SignedRevInfo.RevInfo()
		if err != nil {
			log.Error("Error getting RevInfo from SignedRevInfo", "err", err)
		}
		log.Debug("Forwarding revocation", "revInfo", revInfo.String(), "targets", args.Addrs)
		for _, svcAddr := range args.Addrs {
			r.fwdRevInfo(args.SignedRevInfo, &svcAddr)
		}
	}
}

// fwdRevInfo forwards RevInfo payloads to a designated local host.
func (r *Router) fwdRevInfo(sRevInfo *path_mgmt.SignedRevInfo, dstHost addr.HostAddr) {
	ctx := rctx.Get()
	// Pick first local address from topology as source.
	srcAddr := ctx.Conf.Net.LocAddr[0].PublicAddrInfo(ctx.Conf.Topo.Overlay)
	cpld, err := ctrl.NewPathMgmtPld(sRevInfo, nil, nil)
	if err != nil {
		log.Error("Error generating RevInfo Ctrl payload", "err", err)
		return
	}
	scpld, err := cpld.SignedPld(ctrl.NullSigner)
	if err != nil {
		log.Error("Error generating RevInfo signed Ctrl payload", "err", err)
		return
	}
	if err = r.genPkt(ctx.Conf.IA, *dstHost.(*addr.HostSVC), 0, srcAddr, scpld); err != nil {
		log.Error("Error generating RevInfo packet", "err", err)
	}
}
