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
	"strings"

	//log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/hsr"
	"github.com/netsec-ethz/scion/go/border/packet"
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/util"
)

var (
	dpdkIPs    = flag.String("dpdk-ips", "", "Comma-separated list of IPs for DPDK")
	dpdkIPMap  = make(map[string]bool)
	dpdkAddrMs []hsr.AddrMeta
)

func init() {
	for _, ip := range strings.Split(*dpdkIPs, ",") {
		dpdkIPMap[ip] = true
	}
	setupAddLocalHooks = append(setupAddLocalHooks, ioHSRAddLocal)
}

func ioHSRAddLocal(r *Router, idx int, over *overlay.UDP,
	labels prometheus.Labels) (packet.HookResult, *util.Error) {
	bind := over.BindAddr()
	if _, dpdk := dpdkIPMap[bind.IP.String()]; !dpdk {
		return packet.HookContinue, nil
	}
	dpdkAddrMs = append(dpdkAddrMs, hsr.AddrMeta{GoAddr: bind,
		DirFrom: packet.DirLocal, Labels: labels})
	r.locOutFs[i] = func(p *packet.Packet) {
		r.writeDPDKOutput(p, len(dpdkAddrMs)-1, labels)
	}
	return packet.HookFinish, nil
}

func ioPosixAddExt(r *Router, intf *netconf.Interface,
	labels prometheus.Labels) (packet.HookResult, *util.Error) {
	bind := a.IFAddr.BindAddr()
	if _, dpdk := dpdkIPMap[bind.IP.String()]; !dpdk {
		return packet.HookContinue, nil
	}
	dpdkAddrMs = append(dpdkAddrMs, hsr.AddrMeta{
		GoAddr: bind, DirFrom: packet.DirExternal, Labels: labels})
	r.intfOutFs[a.Id] = func(p *packet.Packet) {
		r.writeDPDKOutput(p, len(dpdkAddrMs)-1, labels)
	}
	return packet.HookFinish, nil
}

func setupHSRNet(r *Router) *util.Error {
	if len(dpdkAddrMs) == 0 {
		return nil
	}
	hsr.Init(r.Id, filepath.Join(conf.C.Dir, ZlogConf), flag.Args(), dpdkAddrMs)
	for i := 0; i < runtime.NumCPU(); i++ {
		q := make(chan *packet.Packet)
		r.inQs = append(r.inQs, q)
		go r.readDPDKInput(q)
	}
	return nil
}
