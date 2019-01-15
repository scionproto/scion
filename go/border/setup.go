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
	Setup(r *Router, ctx *rctx.Ctx, labels prometheus.Labels, oldCtx *rctx.Ctx) error
	// Rollback(r *Router, ctx *rctx.Ctx, oldCtx *rctx.Ctx)
	// Teardown(r *Router, ctx *rctx.Ctx, oldCtx *rctx.Ctx)
}

type extSockOps interface {
	Setup(r *Router, ctx *rctx.Ctx, intfs *netconf.Interface,
		labels prometheus.Labels, oldCtx *rctx.Ctx) error
	// Rollback(r *Router, ctx *rctx.Ctx, intf *netconf.Interface, oldCtx *rctx.Ctx)
	// Teardown(r *Router, ctx *rctx.Ctx, intf *netconf.Interface, oldCtx *rctx.Ctx)
}

// SockOps enable the network stack to be modular. Any network stack that wants
// to be included defines its own init function which adds SockOps to these maps.
var registeredLocSockOps = map[brconf.SockType]locSockOps{}
var registeredExtSockOps = map[brconf.SockType]extSockOps{}

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
	// Clear capabilities after setting up the network.
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
	// TODO(roosd): Eventually, this will be configurable through brconfig.toml.
	sockConf := brconf.SockConf{Default: PosixSock}
	if err := r.setupNet(ctx, oldCtx, sockConf); err != nil {
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
func (r *Router) setupNet(ctx *rctx.Ctx, oldCtx *rctx.Ctx, sockConf brconf.SockConf) error {
	// Validate that the new context is valid with respect to the old context.
	if err := validateCtx(ctx, oldCtx, sockConf); err != nil {
		return err
	}
	// Setup local interface.
	labels := prometheus.Labels{"sock": "loc"}
	if err := registeredLocSockOps[sockConf.Loc()].Setup(r, ctx, labels, oldCtx); err != nil {
		return err
	}
	// Iterate over interfaces, configuring them via provided setup function.
	for _, intf := range ctx.Conf.Net.IFs {
		labels := prometheus.Labels{"sock": fmt.Sprintf("intf:%d", intf.Id)}
		err := registeredExtSockOps[sockConf.Ext(intf.Id)].Setup(r, ctx, intf, labels, oldCtx)
		if err != nil {
			return err
		}
	}
	// Stop input functions that are no longer needed.
	if oldCtx != nil {
		if ctx.LocSockIn != oldCtx.LocSockIn {
			oldCtx.LocSockIn.Stop()
			oldCtx.LocSockOut.Stop()
		}
		for ifid := range oldCtx.ExtSockIn {
			if _, ok := ctx.ExtSockIn[ifid]; !ok {
				oldCtx.ExtSockIn[ifid].Stop()
				oldCtx.ExtSockOut[ifid].Stop()
			}
		}
	}
	return nil
}

// validateCtx ensures that the socket type of existing sockets does not change.
func validateCtx(ctx, oldCtx *rctx.Ctx, sockConf brconf.SockConf) error {
	if oldCtx == nil {
		return nil
	}
	sockType := sockConf.Loc()
	// Validate socket type is registered.
	if _, ok := registeredLocSockOps[sockType]; !ok {
		return common.NewBasicError("No LocSockOps found", nil, "sockType", sockType)
	}
	// Validate local sock of same type.
	if oldCtx.LocSockIn.Type != sockType {
		return common.NewBasicError("Unable to switch local socket type", nil,
			"expected", oldCtx.LocSockIn.Type, "actual", sockType)
	}
	// Validate interfaces.
	for _, intf := range ctx.Conf.Net.IFs {
		sockType := sockConf.Ext(intf.Id)
		// Validate socket type is registered
		if _, ok := registeredExtSockOps[sockType]; !ok {
			return common.NewBasicError("No ExtSockOps found", nil,
				"sockType", sockType, "ifid", intf.Id)
		}
		// Validate same socket type.
		if oldCtx.ExtSockIn[intf.Id] != nil && oldCtx.ExtSockIn[intf.Id].Type != sockType {
			return common.NewBasicError("Unable to switch external socket type", nil,
				"expected", oldCtx.ExtSockIn[intf.Id].Type, "actual", sockType)
		}
	}
	return nil
}
