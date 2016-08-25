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
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/conf"
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
	var addrs []string
	for i, a := range conf.C.Net.LocAddr {
		if err := a.Listen(); err != nil {
			return util.NewError(ErrorListenLocal, "err", err)
		}
		addrs = append(addrs, a.BindAddr().String())
		q := make(chan *packet.Packet)
		r.inQs = append(r.inQs, q)
		go r.readInput(a.Conn, packet.DirLocal, q)
		r.locOutFs[i] = func(p *packet.Packet) { r.writeLocalOutput(a.Conn, p) }
	}
	metrics.Export(addrs)
	for _, a := range conf.C.Net.IFs {
		if err := a.IFAddr.Connect(a.RemoteAddr); err != nil {
			return util.NewError(ErrorListenExternal, "err", err)
		}
		q := make(chan *packet.Packet)
		r.inQs = append(r.inQs, q)
		go r.readInput(a.IFAddr.Conn, packet.DirExternal, q)
		r.intfOutFs[a.Id] = func(p *packet.Packet) { r.writeIntfOutput(a.IFAddr.Conn, p) }
	}
	return nil
}
