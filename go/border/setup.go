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
	"flag"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/hsr"
	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/packet"
	"github.com/netsec-ethz/scion/go/border/path"
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	ErrorTopoIDNotFound = "Unable to find element ID in topology"
	ErrorListenLocal    = "Unable to listen on local socket"
	ErrorListenExternal = "Unable to listen on external socket"
)

const ZlogConf = "zlog.conf"

func (r *Router) setup(confDir string) *util.Error {
	r.locOutFs = make(map[int]packet.OutputFunc)
	r.intfOutFs = make(map[path.IntfID]packet.OutputFunc)
	r.freePkts = make(chan *packet.Packet, 1024)

	if err := conf.Load(r.Id, confDir); err != nil {
		return err
	}
	log.Debug("Topology loaded", "topo", conf.C.BR)
	log.Debug("AS Conf loaded", "conf", conf.C.AS)
	log.Debug("NetConf", "conf", conf.C.Net)

	packet.Init(r.locOutFs, r.intfOutFs, r.ProcessIFStates)
	return nil
}

func (r *Router) setupNet() *util.Error {
	dpdkIPMap := make(map[string]bool)
	for _, ip := range strings.Split(*dpdkIPs, ",") {
		dpdkIPMap[ip] = true
	}
	var addrs []string
	var dpdkAddrMs []hsr.AddrMeta
	for i, a := range conf.C.Net.LocAddr {
		labels := prometheus.Labels{"id": fmt.Sprintf("loc:%d", i)}
		bind := a.BindAddr()
		_, dpdk := dpdkIPMap[bind.IP.String()]
		if dpdk {
			dpdkAddrMs = append(dpdkAddrMs, hsr.AddrMeta{GoAddr: bind,
				DirFrom: packet.DirLocal, Labels: labels})
		} else if err := a.Listen(); err != nil {
			return util.NewError(ErrorListenLocal, "err", err)
		}
		addrs = append(addrs, a.BindAddr().String())
		if dpdk {
			r.locOutFs[i] = func(p *packet.Packet) {
				r.writeDPDKOutput(p, len(dpdkAddrMs)-1, labels)
			}
		} else {
			q := make(chan *packet.Packet)
			r.inQs = append(r.inQs, q)
			go r.readPosixInput(a.Conn, packet.DirLocal, labels, q)
			r.locOutFs[i] = func(p *packet.Packet) { r.writeLocalOutput(a.Conn, labels, p) }
		}
	}
	metrics.Export(addrs)
	for _, a := range conf.C.Net.IFs {
		labels := prometheus.Labels{"id": fmt.Sprintf("intf:%d", a.Id)}
		bind := a.IFAddr.BindAddr()
		_, dpdk := dpdkIPMap[bind.IP.String()]
		if dpdk {
			dpdkAddrMs = append(dpdkAddrMs, hsr.AddrMeta{
				GoAddr: bind, DirFrom: packet.DirExternal, Labels: labels})
		} else if err := a.IFAddr.Connect(a.RemoteAddr); err != nil {
			return util.NewError(ErrorListenExternal, "err", err)
		}
		if dpdk {
			r.intfOutFs[a.Id] = func(p *packet.Packet) {
				r.writeDPDKOutput(p, len(dpdkAddrMs)-1, labels)
			}
		} else {
			q := make(chan *packet.Packet)
			r.inQs = append(r.inQs, q)
			go r.readPosixInput(a.IFAddr.Conn, packet.DirExternal, labels, q)
			r.intfOutFs[a.Id] = func(p *packet.Packet) {
				r.writeIntfOutput(a.IFAddr.Conn, labels, p)
			}
		}
	}
	if len(dpdkAddrMs) > 0 {
		hsr.Init(r.Id, filepath.Join(conf.C.Dir, ZlogConf), flag.Args(), dpdkAddrMs)
		for i := 0; i < runtime.NumCPU(); i++ {
			q := make(chan *packet.Packet)
			r.inQs = append(r.inQs, q)
			go r.readDPDKInput(q)
		}
	}
	return nil
}
