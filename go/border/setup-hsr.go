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

// +build hsr

// This file handles configuring the network interfaces that are managed by
// libhsr (via go/border/hsr).

package main

import (
	"flag"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	//log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/hsr"
	"github.com/netsec-ethz/scion/go/border/netconf"
	"github.com/netsec-ethz/scion/go/border/rctx"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
)

var (
	hsrIPs = flag.String("hsr.ips", "", "Comma-separated list of IPs for HSR")
	// hsrIPMap is used at startup to check if a given IP is managed by libhsr.
	hsrIPMap = make(map[string]bool)
	// See hsr.AddrMs
	hsrAddrMs []hsr.AddrMeta
)

const HSRInputFIdx int = -1

func init() {
	setupNetStartHooks = append(setupNetStartHooks, setupHSRNetStart)
	setupAddLocalHooks = append(setupAddLocalHooks, setupHSRAddLocal)
	setupAddExtHooks = append(setupAddExtHooks, setupHSRAddExt)
	setupNetFinishHooks = append(setupNetFinishHooks, setupHSRNetFinish)
}

func setupHSRNetStart(r *Router, _ *rctx.Ctx, _ *rctx.Ctx) (rpkt.HookResult, error) {
	for _, ip := range strings.Split(*hsrIPs, ",") {
		hsrIPMap[ip] = true
	}
	return rpkt.HookContinue, nil
}

func setupHSRAddLocal(r *Router, ctx *rctx.Ctx, idx int, over *overlay.UDP,
	labels prometheus.Labels, oldCtx *rctx.Ctx) (rpkt.HookResult, error) {
	bind := over.BindAddr()
	if _, hsr := hsrIPMap[bind.IP.String()]; !hsr {
		return rpkt.HookContinue, nil
	}
	// Check if there is already an output function for this index.
	if oldCtx != nil {
		if outf, ok := oldCtx.LocOutFs[idx]; ok {
			ctx.LocOutFs[idx] = outf
			return rpkt.HookFinish, nil
		}
	}

	var ifids []common.IFIDType
	for _, intf := range ctx.Conf.Net.IFs {
		if intf.LocAddrIdx == idx {
			ifids = append(ifids, intf.Id)
		}
	}
	hsrAddrMs = append(hsrAddrMs, hsr.AddrMeta{GoAddr: bind,
		DirFrom: rpkt.DirLocal, IfIDs: ifids, Labels: labels})
	ctx.LocOutFs[idx] = func(oo rctx.OutputObj, dst *net.UDPAddr) {
		writeHSROutput(oo, dst, len(hsrAddrMs)-1, labels)
	}
	return rpkt.HookFinish, nil
}

func setupHSRAddExt(r *Router, ctx *rctx.Ctx, intf *netconf.Interface,
	labels prometheus.Labels, oldCtx *rctx.Ctx) (rpkt.HookResult, error) {
	bind := intf.IFAddr.BindAddr()
	if _, hsr := hsrIPMap[bind.IP.String()]; !hsr {
		return rpkt.HookContinue, nil
	}
	// Check if there is already an output function for this index.
	if oldCtx != nil {
		if outf, ok := oldCtx.IntfOutFs[intf.Id]; ok {
			ctx.IntfOutFs[intf.Id] = outf
			return rpkt.HookFinish, nil
		}
	}
	hsrAddrMs = append(hsrAddrMs, hsr.AddrMeta{
		GoAddr: bind, DirFrom: rpkt.DirExternal, IfIDs: []common.IFIDType{intf.Id}, Labels: labels})
	ctx.IntfOutFs[intf.Id] = func(oo rctx.OutputObj, dst *net.UDPAddr) {
		writeHSROutput(oo, dst, len(hsrAddrMs)-1, labels)
	}
	return rpkt.HookFinish, nil
}

func setupHSRNetFinish(r *Router, ctx *rctx.Ctx,
	oldCtx *rctx.Ctx) (rpkt.HookResult, error) {
	if len(hsrAddrMs) == 0 {
		return rpkt.HookContinue, nil
	}
	if oldCtx != nil {
		if f, ok := oldCtx.LocInputFs[HSRInputFIdx]; ok {
			ctx.LocInputFs[HSRInputFIdx] = f
			return rpkt.HookContinue, nil
		}
	}
	err := hsr.Init(filepath.Join(ctx.Conf.Dir, fmt.Sprintf("%s.zlog.conf", r.Id)),
		flag.Args(), hsrAddrMs)
	if err != nil {
		return rpkt.HookError, err
	}
	ctx.LocInputFs[HSRInputFIdx] = &HSRInput{
		Router:      r,
		StopChan:    make(chan struct{}),
		StoppedChan: make(chan struct{}),
		Func:        readHSRInput,
	}
	return rpkt.HookContinue, nil
}
