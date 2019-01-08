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

// This file handles the router setup, from getting the config loaded, to
// configuring the network interfaces, and starting the input goroutines.
// Support for POSIX(/BSD) sockets is included here, with hooks to allow other
// network stacks to be loaded instead/additionally.

package main

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/syndtr/gocapability/capability"

	"github.com/scionproto/scion/go/border/brconf"
	"github.com/scionproto/scion/go/border/ifstate"
	"github.com/scionproto/scion/go/border/netconf"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
)

type locSockOps interface {
	Setup(*Router, *rctx.Ctx, prometheus.Labels, *rctx.Ctx) error
}

type extSockOps interface {
	Setup(*Router, *rctx.Ctx, *netconf.Interface, prometheus.Labels, *rctx.Ctx) error
}

// SockOps enable the network stack to be modular. Any network stack that wants
// to be included defines its own init function which adds SockOps to these maps.
var registeredLocSockOps = map[rctx.SocketType]locSockOps{}
var registeredExtSockOps = map[rctx.SocketType]extSockOps{}

type setupNetHook func(r *Router, ctx *rctx.Ctx,
	oldCtx *rctx.Ctx) (rpkt.HookResult, error)

// Setup hooks enables the network stack to be modular. Any network stack that
// wants to be included defines its own init function which adds hooks to these
// hook slices. See setup-hsr.go for an example.
var setupNetStartHooks []setupNetHook
var setupNetFinishHooks []setupNetHook

// DefaultSockType is the default socket type that is returned by SocketConf.
var DefaultSockType = PosixSock

type SocketConf struct {
	LocalType     rctx.SocketType
	ExternalTypes map[common.IFIDType]rctx.SocketType
}

func (s SocketConf) Loc() rctx.SocketType {
	if s.LocalType != "" {
		return s.LocalType
	}
	return DefaultSockType
}

func (s SocketConf) Ext(ifid common.IFIDType) rctx.SocketType {
	if t := s.ExternalTypes[ifid]; t != "" {
		return t
	}
	return DefaultSockType
}

// setup creates the router's channels and map, sets up the rpkt package, and
// sets up a new router context. This function can only be called once during startup.
func (r *Router) setup() error {
	r.freePkts = ringbuf.New(1024, func() interface{} {
		return rpkt.NewRtrPkt()
	}, "free", prometheus.Labels{"ringId": "freePkts"})
	r.sRevInfoQ = make(chan rpkt.RawSRevCallbackArgs, 16)
	r.pktErrorQ = make(chan pktErrorArgs, 16)

	// Configure the rpkt package with the callbacks it needs.
	rpkt.Init(r.RawSRevCallback)

	// Load config.
	var err error
	var conf *brconf.Conf
	if conf, err = r.loadNewConfig(); err != nil {
		return err
	}
	// Setup new context.
	if err = r.setupNewContext(conf); err != nil {
		return err
	}
	// Clear capabilities after setting up the network. Capabilities are currently
	// only needed by the HSR for which the router never reconfigures the network.
	if err = r.clearCapabilities(); err != nil {
		return err
	}
	config.Metrics.StartPrometheus()
	return nil
}

// clearCapabilities drops unnecessary capabilities after startup
func (r *Router) clearCapabilities() error {
	caps, err := capability.NewPid(0)
	if err != nil {
		return common.NewBasicError("Error retrieving capabilities", err)
	}
	log.Debug("Startup capabilities", "caps", caps)
	caps.Clear(capability.CAPS)
	caps.Apply(capability.CAPS)
	caps.Load()
	log.Debug("Cleared capabilities", "caps", caps)
	return nil
}

// loadNewConfig loads a new brconf.Conf object from the configuration file.
func (r *Router) loadNewConfig() (*brconf.Conf, error) {
	var config *brconf.Conf
	var err error
	if config, err = brconf.Load(r.Id, r.confDir); err != nil {
		return nil, common.NewBasicError("Failed to load topology config", err, "dir", r.confDir)
	}
	log.Debug("Topology and AS config loaded", "IA", config.IA, "IfIDs", config.BR,
		"dir", r.confDir)
	return config, nil
}

// setupNewContext sets up a new router context.
func (r *Router) setupNewContext(config *brconf.Conf) error {
	oldCtx := rctx.Get()
	ctx := rctx.New(config)
	if err := r.setupNet(ctx, oldCtx, SocketConf{}); err != nil {
		return err
	}
	rctx.Set(ctx)
	startSocks(ctx)
	// Clean-up interface state infos that are not present anymore.
	if oldCtx != nil {
		for ifID := range oldCtx.Conf.Topo.IFInfoMap {
			if _, ok := ctx.Conf.Topo.IFInfoMap[ifID]; !ok {
				ifstate.DeleteState(ifID)
			}
		}
	}
	return nil
}

// startSocks starts all sockets for the given context.
func startSocks(ctx *rctx.Ctx) {
	// Start local input functions.
	ctx.LocSockIn.Start()
	// Start local output functions.
	ctx.LocSockOut.Start()
	// Start external input functions.
	for _, s := range ctx.ExtSockIn {
		s.Start()
	}
	// Start external output functions.
	for _, s := range ctx.ExtSockOut {
		s.Start()
	}
}

// setupNet configures networking for the router, using any setup hooks that
// have been registered. If an old context is provided, setupNet reconfigures
// networking, e.g., starting/stopping new/old input routines if necessary.
func (r *Router) setupNet(ctx *rctx.Ctx, oldCtx *rctx.Ctx, sockConf SocketConf) error {
	// Run startup hooks, if any.
	for _, f := range setupNetStartHooks {
		ret, err := f(r, ctx, oldCtx)
		switch {
		case err != nil:
			return err
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break
		}
	}
	// Setup local interface.
	if err := r.setupLocSocks(ctx, oldCtx, sockConf); err != nil {
		return err
	}
	// Setup external interfaces.
	if err := r.setupExtSocks(ctx, oldCtx, sockConf); err != nil {
		return err
	}
	// Run finish hooks, if any.
	for _, f := range setupNetFinishHooks {
		ret, err := f(r, ctx, oldCtx)
		switch {
		case err != nil:
			return err
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break
		}
	}
	// Stop input functions that are no longer needed.
	if oldCtx != nil {
		if ctx.LocSockIn != oldCtx.LocSockIn {
			stopSock(oldCtx.LocSockIn)
			stopSock(oldCtx.LocSockOut)
		}
		for ifid, sock := range oldCtx.ExtSockIn {
			if _, ok := ctx.ExtSockIn[ifid]; !ok {
				stopSock(sock)
				stopSock(oldCtx.ExtSockOut[ifid])
			}
		}
	}
	return nil
}

func (r *Router) setupLocSocks(ctx *rctx.Ctx, oldCtx *rctx.Ctx, sockConf SocketConf) error {
	locSockType := sockConf.Loc()
	ops, ok := registeredLocSockOps[locSockType]
	if !ok {
		return common.NewBasicError("No LocSockOps found", nil, "sockType", locSockType)
	}
	if oldCtx != nil && oldCtx.LocSockIn != nil && oldCtx.LocSockIn.Type != locSockType {
		return common.NewBasicError("Unable to switch local socket type", nil,
			"expected", oldCtx.LocSockIn.Type, "actual", locSockType)
	}
	labels := prometheus.Labels{"sock": "loc"}
	if err := ops.Setup(r, ctx, labels, oldCtx); err != nil {
		return err
	}
	return nil
}

func (r *Router) setupExtSocks(ctx *rctx.Ctx, oldCtx *rctx.Ctx, sockConf SocketConf) error {
	// Iterate over interfaces, configuring them via provided setup function.
	for _, intf := range ctx.Conf.Net.IFs {
		sockType := sockConf.Ext(intf.Id)
		ops, ok := registeredExtSockOps[sockType]
		if !ok {
			return common.NewBasicError("No ExtSockOps found", nil, "sockType", sockType)
		}
		if oldCtx != nil && oldCtx.ExtSockIn[intf.Id] != nil &&
			oldCtx.ExtSockIn[intf.Id].Type != sockType {
			return common.NewBasicError("Unable to switch external socket type", nil,
				"expected", oldCtx.ExtSockIn[intf.Id].Type, "actual", sockType)
		}
		labels := prometheus.Labels{"sock": fmt.Sprintf("intf:%d", intf.Id)}
		if err := ops.Setup(r, ctx, intf, labels, oldCtx); err != nil {
			return err
		}
	}
	return nil
}

func stopSock(s *rctx.Sock) {
	if s != nil {
		s.Stop()
	}
}
