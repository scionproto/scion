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
	"crypto/sha1"
	"path/filepath"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/pbkdf2"

	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/netconf"
	"github.com/netsec-ethz/scion/go/border/packet"
	"github.com/netsec-ethz/scion/go/border/path"
	"github.com/netsec-ethz/scion/go/lib/as_conf"
	"github.com/netsec-ethz/scion/go/lib/topology"
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	ErrorTopoIDNotFound = "Unable to find element ID in topology"
	ErrorListenLocal    = "Unable to listen on local socket"
	ErrorListenExternal = "Unable to listen on external socket"
)

func (r *Router) setup(confDir string) *util.Error {
	var err *util.Error
	r.locOutQs = make(map[int]packet.OutputFunc)
	r.intfOutQs = make(map[path.IntfID]packet.OutputFunc)
	r.freePkts = make(chan *packet.Packet, 1024)

	topoPath := filepath.Join(confDir, topology.CfgName)
	if err = topology.Load(topoPath); err != nil {
		return err
	}
	topoBR, ok := topology.Curr.T.BR[r.Id]
	if !ok {
		return util.NewError(ErrorTopoIDNotFound, "id", r.Id, "path", topoPath)
	}
	r.Topo = &topoBR
	log.Debug("Topology loaded", "topo", topoBR, "path", topoPath)

	asConfPath := filepath.Join(confDir, as_conf.CfgName)
	if err = as_conf.Load(asConfPath); err != nil {
		return err
	}
	r.ASConf = as_conf.CurrConf
	log.Debug("AS Conf", "conf", r.ASConf, "path", asConfPath)
	// Generate key of length 16 with 1000 hash iterations, which is the same as
	// the defaults used by pycrypto.
	hfGenKey := pbkdf2.Key(r.ASConf.MasterASKey, []byte("Derive OF Key"), 1000, 16, sha1.New)
	if r.HFGenBlock, err = util.InitAES(hfGenKey); err != nil {
		return err
	}

	r.NetConf = netconf.FromTopo(r.Topo)
	log.Debug("NetConf", "conf", r.NetConf)

	packet.Init(topology.Curr, r.NetConf, r.locOutQs, r.intfOutQs, r.HFGenBlock)
	return nil
}

func (r *Router) startup() *util.Error {
	if err := r.setupNet(); err != nil {
		return err
	}
	go r.SyncInterface()
	go r.IFStateUpdate()
	return nil
}

func (r *Router) setupNet() *util.Error {
	var addrs []string
	for i, a := range r.NetConf.LocAddr {
		if err := a.Listen(); err != nil {
			return util.NewError(ErrorListenLocal, "err", err)
		}
		addrs = append(addrs, a.BindAddr().String())
		q := make(chan *packet.Packet)
		r.inQs = append(r.inQs, q)
		go r.readInput(a.Conn, packet.DirLocal, q)
		r.locOutQs[i] = func(p *packet.Packet) { r.writeLocalOutput(a.Conn, p) }
	}
	metrics.Export(addrs)
	for _, a := range r.NetConf.IFs {
		if err := a.IFAddr.Connect(a.RemoteAddr); err != nil {
			return util.NewError(ErrorListenExternal, "err", err)
		}
		q := make(chan *packet.Packet)
		r.inQs = append(r.inQs, q)
		go r.readInput(a.IFAddr.Conn, packet.DirExternal, q)
		r.intfOutQs[a.Id] = func(p *packet.Packet) { r.writeIntfOutput(a.IFAddr.Conn, p) }
	}
	return nil
}
