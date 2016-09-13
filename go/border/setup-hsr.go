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

package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	//log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/hsr"
	"github.com/netsec-ethz/scion/go/border/netconf"
	"github.com/netsec-ethz/scion/go/border/packet"
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/util"
)

var (
	hsrIPs    = flag.String("hsr.ips", "", "Comma-separated list of IPs for HSR")
	hsrIPMap  = make(map[string]bool)
	hsrAddrMs []hsr.AddrMeta
)

func init() {
	setupNetStartHooks = append(setupNetStartHooks, setupHSRNetStart)
	setupAddLocalHooks = append(setupAddLocalHooks, setupHSRAddLocal)
	setupAddExtHooks = append(setupAddExtHooks, setupHSRAddExt)
	setupNetFinishHooks = append(setupNetFinishHooks, setupHSRNetFinish)
}

func setupHSRNetStart(r *Router) (packet.HookResult, *util.Error) {
	for _, ip := range strings.Split(*hsrIPs, ",") {
		hsrIPMap[ip] = true
	}
	return packet.HookContinue, nil
}

func setupHSRAddLocal(r *Router, idx int, over *overlay.UDP,
	labels prometheus.Labels) (packet.HookResult, *util.Error) {
	bind := over.BindAddr()
	if _, hsr := hsrIPMap[bind.IP.String()]; !hsr {
		return packet.HookContinue, nil
	}
	hsrAddrMs = append(hsrAddrMs, hsr.AddrMeta{GoAddr: bind,
		DirFrom: packet.DirLocal, Labels: labels})
	r.locOutFs[idx] = func(p *packet.Packet) {
		r.writeHSROutput(p, len(hsrAddrMs)-1, labels)
	}
	return packet.HookFinish, nil
}

func setupHSRAddExt(r *Router, intf *netconf.Interface,
	labels prometheus.Labels) (packet.HookResult, *util.Error) {
	bind := intf.IFAddr.BindAddr()
	if _, hsr := hsrIPMap[bind.IP.String()]; !hsr {
		return packet.HookContinue, nil
	}
	hsrAddrMs = append(hsrAddrMs, hsr.AddrMeta{
		GoAddr: bind, DirFrom: packet.DirExternal, Labels: labels})
	r.intfOutFs[intf.Id] = func(p *packet.Packet) {
		r.writeHSROutput(p, len(hsrAddrMs)-1, labels)
	}
	return packet.HookFinish, nil
}

func setupHSRNetFinish(r *Router) (packet.HookResult, *util.Error) {
	if len(hsrAddrMs) == 0 {
		return packet.HookContinue, nil
	}
	err := hsr.Init(filepath.Join(conf.C.Dir, fmt.Sprintf("%s.zlog.conf", r.Id)),
		flag.Args(), hsrAddrMs)
	if err != nil {
		return packet.HookError, err
	}
	q := make(chan *packet.Packet)
	r.inQs = append(r.inQs, q)
	go r.readHSRInput(q)
	return packet.HookContinue, nil
}
