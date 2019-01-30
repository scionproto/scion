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
	"github.com/scionproto/scion/go/border/netconf"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/proto"
)

type locSockOps interface {
	Setup(r *Router, ctx *rctx.Ctx, labels prometheus.Labels, oldCtx *rctx.Ctx) error
	Rollback(r *Router, ctx *rctx.Ctx, labels prometheus.Labels, oldCtx *rctx.Ctx) error
}

type extSockOps interface {
	Setup(r *Router, ctx *rctx.Ctx, intfs *netconf.Interface,
		labels prometheus.Labels, oldCtx *rctx.Ctx) error
	Rollback(r *Router, ctx *rctx.Ctx, intfs *netconf.Interface,
		labels prometheus.Labels, oldCtx *rctx.Ctx) error
	Teardown(r *Router, ctx *rctx.Ctx, intfs *netconf.Interface, oldCtx *rctx.Ctx)
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
	// Initialize itopo.
	itopo.Init(r.Id, proto.ServiceType_br, itopo.Callbacks{})
	if _, _, err := itopo.SetStatic(conf.Topo, true); err != nil {
		return err
	}
	// Setup new context.
	if err = r.setupCtxFromConfig(conf); err != nil {
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

// setupCtxFromConfig sets up a new router context from the loaded config.
// This method is called on initial start and when a sighup is received.
func (r *Router) setupCtxFromConfig(config *brconf.Conf) error {
	log.Debug("====> Setting up new context from config")
	// We want to keep in sync itopo and the context that is set.
	// We attempt to set the context with the topology that will be current
	// after setting itopo. If setting itopo fails in the end, we rollback the context.
	tx, err := itopo.BeginSetStatic(config.Topo, true)
	if err != nil {
		return err
	}
	// Set config to use the appropriate topology. The returned topology is
	// not necessarily the same as config.Topo. It can be another static
	// or dynamic topology.
	newConf, err := brconf.WithNewTopo(r.Id, tx.Get(), config)
	if err != nil {
		return err
	}
	return r.setupNewContext(rctx.New(newConf), tx)
}

// setupNewContext sets up a new router context.
func (r *Router) setupNewContext(ctx *rctx.Ctx, tx itopo.Transaction) error {
	oldCtx := rctx.Get()
	// TODO(roosd): Eventually, this will be configurable through brconfig.toml.
	sockConf := brconf.SockConf{Default: PosixSock}
	if err := r.setupNetAndTopo(ctx, oldCtx, sockConf, tx); err != nil {
		r.rollbackNet(ctx, oldCtx, sockConf, handleRollbackErr)
		return err
	}
	rctx.Set(ctx)
	startSocks(ctx)
	// Tear down sockets for removed interfaces
	r.teardownNet(ctx, oldCtx, sockConf)
	return nil
}

// setupNetAndTopo sets up the net context and set the topology in itopo.
func (r *Router) setupNetAndTopo(ctx *rctx.Ctx, oldCtx *rctx.Ctx,
	sockConf brconf.SockConf, tx itopo.Transaction) error {

	if err := r.setupNet(ctx, oldCtx, sockConf); err != nil {
		return err
	}
	return tx.Commit()
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
	if err := registeredLocSockOps[sockConf.Loc()].Setup(r, ctx, locLabels(), oldCtx); err != nil {
		return err
	}
	// Iterate over interfaces, configuring them via provided setup function.
	for _, intf := range ctx.Conf.Net.IFs {
		labels := extLabels(intf.Id)
		err := registeredExtSockOps[sockConf.Ext(intf.Id)].Setup(r, ctx, intf, labels, oldCtx)
		if err != nil {
			return err
		}
	}
	return nil
}

// rollbackNet rolls back the changes of a failed call to setupNet.
func (r *Router) rollbackNet(ctx, oldCtx *rctx.Ctx,
	sockConf brconf.SockConf, handleErr func(err error)) {

	// Rollback of external interfaces.
	for _, intf := range ctx.Conf.Net.IFs {
		labels := extLabels(intf.Id)
		err := registeredExtSockOps[sockConf.Ext(intf.Id)].Rollback(r, ctx, intf, labels, oldCtx)
		if err != nil {
			handleErr(common.NewBasicError("Unable to rollback external interface",
				err, "intf", intf))
		}
	}
	// Rollback of local interface.
	err := registeredLocSockOps[sockConf.Loc()].Rollback(r, ctx, locLabels(), oldCtx)
	if err != nil {
		handleErr(common.NewBasicError("Unable to rollback local interface", err))
	}
	if oldCtx != nil {
		// Start sockets that are possibly created by rollback.
		startSocks(oldCtx)
	}
}

// teardownOldNet tears down the sockets of removed external interfaces.
func (r *Router) teardownNet(ctx, oldCtx *rctx.Ctx, sockConf brconf.SockConf) {
	if oldCtx == nil {
		return
	}
	// Iterate on oldCtx to catch removed interfaces.
	for _, intf := range oldCtx.Conf.Net.IFs {
		registeredExtSockOps[sockConf.Ext(intf.Id)].Teardown(r, ctx, intf, oldCtx)
	}
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

func handleRollbackErr(err error) {
	if config.BR.RollbackFailAction != brconf.FailActionContinue {
		fatal.Fatal(err)
	}
	log.Crit("Error in rollback", "err", err)
}

func locLabels() prometheus.Labels {
	return prometheus.Labels{"sock": "loc"}
}

func extLabels(id common.IFIDType) prometheus.Labels {
	return prometheus.Labels{"sock": fmt.Sprintf("intf:%d", id)}
}

// validateCtx ensures that the socket type of existing sockets does not change
// and that an address is not take over by one interfaces from another.
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

		// Validate interface does not take over local address.
		if intf.IFAddr.Equal(oldCtx.Conf.Net.LocAddr) {
			return common.NewBasicError("Address must not switch from local", nil,
				"intf", intf, "locAddr", oldCtx.Conf.Net.LocAddr)
		}
		for _, oldIntf := range oldCtx.Conf.Net.IFs {
			// Validate interface does not take over the address of old interface.
			if intf.IFAddr.Equal(oldIntf.IFAddr) && intf.Id != oldIntf.Id {
				return common.NewBasicError("Address must not switch interface", nil,
					"intf", intf, "oldIntf", oldIntf)
			}
			// Validate local sock does not take over the address of old interface.
			if ctx.Conf.Net.LocAddr.Equal(oldIntf.IFAddr) {
				return common.NewBasicError("Address must not switch to local", nil,
					"oldIntf", intf, "locAddr", oldCtx.Conf.Net.LocAddr)
			}
		}
	}
	return nil
}
