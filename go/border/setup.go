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
	"fmt"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/syndtr/gocapability/capability"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/netconf"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	ErrorTopoIDNotFound = "Unable to find element ID in topology"
	ErrorListenLocal    = "Unable to listen on local socket"
	ErrorListenExternal = "Unable to listen on external socket"
)

type setupNetHook func(r *Router) (rpkt.HookResult, *util.Error)
type setupAddLocalHook func(r *Router, idx int, over *overlay.UDP, labels prometheus.Labels) (
	rpkt.HookResult, *util.Error)
type setupAddExtHook func(r *Router, intf *netconf.Interface, labels prometheus.Labels) (
	rpkt.HookResult, *util.Error)

var setupNetStartHooks []setupNetHook
var setupAddLocalHooks []setupAddLocalHook
var setupAddExtHooks []setupAddExtHook
var setupNetFinishHooks []setupNetHook

func (r *Router) setup(confDir string) *util.Error {
	r.locOutFs = make(map[int]rpkt.OutputFunc)
	r.intfOutFs = make(map[spath.IntfID]rpkt.OutputFunc)
	r.freePkts = make(chan *rpkt.RPkt, 1024)
	r.revInfoQ = make(chan util.RawBytes)

	if err := conf.Load(r.Id, confDir); err != nil {
		return err
	}
	log.Debug("Topology loaded", "topo", conf.C.BR)
	log.Debug("AS Conf loaded", "conf", conf.C.AS)
	log.Debug("NetConf", "conf", conf.C.Net)

	rpkt.Init(r.locOutFs, r.intfOutFs, r.ProcessIFStates, r.RevTokenCallback)
	return nil
}

func (r *Router) setupNet() *util.Error {
	// If there are other hooks, they should install themselves via init(), so
	// they appear before the posix ones.
	setupAddLocalHooks = append(setupAddLocalHooks, setupPosixAddLocal)
	setupAddExtHooks = append(setupAddExtHooks, setupPosixAddExt)
	for _, f := range setupNetStartHooks {
		ret, err := f(r)
		switch {
		case err != nil:
			return err
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break
		}
	}
	var addrs []string
	for i, a := range conf.C.Net.LocAddr {
		addrs = append(addrs, a.BindAddr().String())
		labels := prometheus.Labels{"id": fmt.Sprintf("loc:%d", i)}
		for _, f := range setupAddLocalHooks {
			ret, err := f(r, i, a, labels)
			switch {
			case err != nil:
				return err
			case ret == rpkt.HookContinue:
				continue
			case ret == rpkt.HookFinish:
				break
			}
		}
	}
	metrics.Export(addrs)
	for _, intf := range conf.C.Net.IFs {
		labels := prometheus.Labels{"id": fmt.Sprintf("intf:%d", intf.Id)}
	InnerLoop:
		for _, f := range setupAddExtHooks {
			ret, err := f(r, intf, labels)
			switch {
			case err != nil:
				return err
			case ret == rpkt.HookContinue:
				continue
			case ret == rpkt.HookFinish:
				break InnerLoop
			}
		}
	}
	for _, f := range setupNetFinishHooks {
		ret, err := f(r)
		switch {
		case err != nil:
			return err
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break
		}
	}
	// drop cap privileges, if any
	caps, err := capability.NewPid(0)
	if err != nil {
		return util.NewError("Error retrieving capabilities", "err", err)
	}
	log.Debug("Startup capabilities", "caps", caps)
	caps.Clear(capability.CAPS)
	caps.Apply(capability.CAPS)
	caps.Load()
	log.Debug("Cleared capabilities", "caps", caps)
	return nil
}

func setupPosixAddLocal(r *Router, idx int, over *overlay.UDP,
	labels prometheus.Labels) (rpkt.HookResult, *util.Error) {
	if err := over.Listen(); err != nil {
		return rpkt.HookError, util.NewError(ErrorListenLocal, "err", err)
	}
	q := make(chan *rpkt.RPkt)
	r.inQs = append(r.inQs, q)
	go r.readPosixInput(over.Conn, rpkt.DirLocal, labels, q)
	r.locOutFs[idx] = func(p *rpkt.RPkt) { r.writeLocalOutput(over.Conn, labels, p) }
	return rpkt.HookFinish, nil
}

func setupPosixAddExt(r *Router, intf *netconf.Interface,
	labels prometheus.Labels) (rpkt.HookResult, *util.Error) {
	if err := intf.IFAddr.Connect(intf.RemoteAddr); err != nil {
		return rpkt.HookError, util.NewError(ErrorListenExternal, "err", err)
	}
	q := make(chan *rpkt.RPkt)
	r.inQs = append(r.inQs, q)
	go r.readPosixInput(intf.IFAddr.Conn, rpkt.DirExternal, labels, q)
	r.intfOutFs[intf.Id] = func(p *rpkt.RPkt) {
		r.writeIntfOutput(intf.IFAddr.Conn, labels, p)
	}
	return rpkt.HookFinish, nil
}
