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

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/hsr"
	"github.com/netsec-ethz/scion/go/border/netconf"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/spath"
)

var (
	hsrIPs = flag.String("hsr.ips", "", "Comma-separated list of IPs for HSR")
	// hsrIPMap is used at startup to check if a given IP is managed by libhsr.
	hsrIPMap = make(map[string]bool)
	// See hsr.AddrMs
	hsrAddrMs []hsr.AddrMeta
)

func init() {
	setupNetStartHooks = append(setupNetStartHooks, setupHSRNetStart)
	setupAddLocalHooks = append(setupAddLocalHooks, setupHSRAddLocal)
	setupAddExtHooks = append(setupAddExtHooks, setupHSRAddExt)
	setupNetFinishHooks = append(setupNetFinishHooks, setupHSRNetFinish)
}

func setupHSRNetStart(r *Router) (rpkt.HookResult, *common.Error) {
	for _, ip := range strings.Split(*hsrIPs, ",") {
		hsrIPMap[ip] = true
	}
	return rpkt.HookContinue, nil
}

func setupHSRAddLocal(r *Router, idx int, over *overlay.UDP,
	labels prometheus.Labels) (rpkt.HookResult, *common.Error) {
	bind := over.BindAddr()
	if _, hsr := hsrIPMap[bind.IP.String()]; !hsr {
		return rpkt.HookContinue, nil
	}
	var ifids []spath.IntfID
	for _, intf := range conf.C.Net.IFs {
		if intf.LocAddrIdx == idx {
			ifids = append(ifids, intf.Id)
		}
	}
	hsrAddrMs = append(hsrAddrMs, hsr.AddrMeta{GoAddr: bind,
		DirFrom: rpkt.DirLocal, IfIDs: ifids, Labels: labels})
	r.locOutFs[idx] = func(rp *rpkt.RtrPkt, dst *net.UDPAddr) {
		r.writeHSROutput(rp, dst, len(hsrAddrMs)-1, labels)
	}
	return rpkt.HookFinish, nil
}

func setupHSRAddExt(r *Router, intf *netconf.Interface,
	labels prometheus.Labels) (rpkt.HookResult, *common.Error) {
	bind := intf.IFAddr.BindAddr()
	if _, hsr := hsrIPMap[bind.IP.String()]; !hsr {
		return rpkt.HookContinue, nil
	}
	hsrAddrMs = append(hsrAddrMs, hsr.AddrMeta{
		GoAddr: bind, DirFrom: rpkt.DirExternal, IfIDs: []spath.IntfID{intf.Id}, Labels: labels})
	r.intfOutFs[intf.Id] = func(rp *rpkt.RtrPkt, dst *net.UDPAddr) {
		r.writeHSROutput(rp, dst, len(hsrAddrMs)-1, labels)
	}
	return rpkt.HookFinish, nil
}

func setupHSRNetFinish(r *Router) (rpkt.HookResult, *common.Error) {
	if len(hsrAddrMs) == 0 {
		return rpkt.HookContinue, nil
	}
	err := hsr.Init(filepath.Join(conf.C.Dir, fmt.Sprintf("%s.zlog.conf", r.Id)),
		flag.Args(), hsrAddrMs)
	if err != nil {
		return rpkt.HookError, err
	}
	q := make(chan *rpkt.RtrPkt)
	r.inQs = append(r.inQs, q)
	go r.readHSRInput(q)
	return rpkt.HookContinue, nil
}
